#include <wraplock.hpp>

namespace eosio {


//adds a proof to the list of processed proofs (throws an exception if proof already exists)
void wraplock::add_or_assert(const bridge::actionproof& actionproof, const name& payer){

    auto pid_index = _processedtable.get_index<"digest"_n>();

    std::vector<char> serializedAction = pack(actionproof.action);
    std::vector<char> serializedReceipt = pack(actionproof.receipt);
    checksum256 action_digest = sha256(serializedAction.data(), serializedAction.size());
    checksum256 action_receipt_digest = sha256(serializedReceipt.data(), serializedReceipt.size());

    auto p_itr = pid_index.find(action_receipt_digest);

    check(p_itr == pid_index.end(), "action already proved");

    _processedtable.emplace( payer, [&]( auto& s ) {
        s.id = _processedtable.available_primary_key();
        s.receipt_digest = action_receipt_digest;
    });

}

void wraplock::init(const checksum256& chain_id, const name& bridge_contract, const checksum256& paired_chain_id)
{
    require_auth( _self );

    auto global = global_config.get_or_create(_self, globalrow);
    global.chain_id = chain_id;
    global.bridge_contract = bridge_contract;
    global.paired_chain_id = paired_chain_id;
    global.enabled = true;
    global_config.set(global, _self);

}

void wraplock::addcontract(const name& native_token_contract, const name& paired_wraptoken_contract)
{
    check(global_config.exists(), "contract must be initialized first");

    require_auth( _self );

    auto itr = _contractmappingtable.find( native_token_contract.value );
    check( itr == _contractmappingtable.end(), "contract already registered");

    _contractmappingtable.emplace( _self, [&]( auto& c ){
        c.native_token_contract = native_token_contract;
        c.paired_wraptoken_contract = paired_wraptoken_contract;
    });
}

void wraplock::delcontract(const name& native_token_contract)
{
    check(global_config.exists(), "contract must be initialized first");

    require_auth( _self );

    auto itr = _contractmappingtable.find( native_token_contract.value );
    check( itr != _contractmappingtable.end(), "contract not registered");

    _contractmappingtable.erase(itr);
}

//emits an xfer receipt to serve as proof in interchain transfers
void wraplock::emitxfer(const wraplock::xfer& xfer){

    check(global_config.exists(), "contract must be initialized first");
 
    require_auth(_self);

}

//Disable all user actions on the contract.
void wraplock::disable(){

    check(global_config.exists(), "contract must be initialized first");
 
    require_auth(_self);

    auto global = global_config.get();
    global.enabled = false;
    global_config.set(global, _self);

}

//Enable all user actions on the contract.
void wraplock::enable(){

    check(global_config.exists(), "contract must be initialized first");
 
    require_auth(_self);

    auto global = global_config.get();
    global.enabled = true;
    global_config.set(global, _self);

}

void wraplock::sub_reserve( const extended_asset& value ){

   reserves _reservestable( _self, value.contract.value );
   const auto& res = _reservestable.get( value.quantity.symbol.code().raw(), "no balance object found" );
   check( res.balance.amount >= value.quantity.amount, "overdrawn balance" );

   _reservestable.modify( res, _self, [&]( auto& a ) {
         a.balance -= value.quantity;
      });
}

void wraplock::add_reserve(const extended_asset& value){

   reserves _reservestable( _self, value.contract.value );
   auto res = _reservestable.find(  value.quantity.symbol.code().raw() );
   if( res == _reservestable.end() ) {
      _reservestable.emplace( _self, [&]( auto& a ){
        a.balance = value.quantity;
      });
   } else {
      _reservestable.modify( res, _self, [&]( auto& a ) {
        a.balance += value.quantity;
      });
   }

}

// called on transfer action to lock tokens and initiate interchain transfer
void wraplock::deposit(name from, name to, asset quantity, string memo)
{ 

    print("transfer ", name{from}, " ",  name{to}, " ", quantity, "\n");
    print("sender: ", get_sender(), "\n");
    
    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    auto contractmap = _contractmappingtable.find( get_sender().value );
    check(contractmap != _contractmappingtable.end(), "transfer not permitted from unauthorised token contract");

    //if incoming transfer
    if (from == "eosio.stake"_n) return ; //ignore unstaking transfers
    else if (to == get_self() && from != get_self()){
      //ignore outbound transfers from this contract, as well as inbound transfers of tokens internal to this contract
      //otherwise, locks the tokens in the reserve and calls emitxfer to be used for issue/cancel proof

      check(memo.size() > 0, "memo must contain valid account name");

      check(quantity.amount > 0, "must lock positive quantity");

      add_reserve( extended_asset{quantity, get_sender()} );

      auto global = global_config.get();

      wraplock::xfer x = {
        .owner = from,
        .quantity = extended_asset(quantity, get_sender()),
        .beneficiary = name(memo)
      };

      wraplock::emitxfer_action act(_self, permission_level{_self, "active"_n});
      act.send(x);

    }

}

void wraplock::_withdraw(const name& prover, const bridge::actionproof actionproof){
    auto global = global_config.get();

    auto contractmap_index = _contractmappingtable.get_index<"wraptoken"_n>();
    auto contractmap = contractmap_index.find( actionproof.action.account.value );
    check(contractmap != contractmap_index.end(), "proof account does not match paired account");

    wraplock::xfer redeem_act = unpack<wraplock::xfer>(actionproof.action.data);

    add_or_assert(actionproof, prover);

    check(actionproof.action.name == "emitxfer"_n, "must provide proof of token retiring before withdrawing");

    sub_reserve( extended_asset{redeem_act.quantity.quantity, redeem_act.quantity.contract} );

    wraplock::transfer_action act(redeem_act.quantity.contract, permission_level{_self, "active"_n});
    act.send(_self, redeem_act.beneficiary, redeem_act.quantity.quantity, std::string("") );

}

// withdraw tokens (requires a heavy proof of retiring)
void wraplock::withdrawa(const name& prover, const bridge::heavyproof blockproof, const bridge::actionproof actionproof){
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _heavy_proof.get_or_create(_self, _heavy_proof_obj);
    p.hp = blockproof;
    _heavy_proof.set(p, _self);
    wraplock::heavyproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _withdraw(prover, actionproof);
}

// withdraw tokens (requires a light proof of retiring)
void wraplock::withdrawb(const name& prover, const bridge::lightproof blockproof, const bridge::actionproof actionproof){
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _light_proof.get_or_create(_self, _light_proof_obj);
    p.lp = blockproof;
    _light_proof.set(p, _self);
    wraplock::lightproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _withdraw(prover, actionproof);
}

void wraplock::_cancel(const name& prover, const bridge::actionproof actionproof)
{
    auto global = global_config.get();

    auto contractmap_index = _contractmappingtable.get_index<"wraptoken"_n>();
    auto contractmap = contractmap_index.find( actionproof.action.account.value );
    check(contractmap != contractmap_index.end(), "proof account does not match paired account");

    wraplock::xfer redeem_act = unpack<wraplock::xfer>(actionproof.action.data);

    add_or_assert(actionproof, prover);

    auto sym = redeem_act.quantity.quantity.symbol;
    check( sym.is_valid(), "invalid symbol name" );

    check(actionproof.action.name == "emitxfer"_n, "must provide proof of token retiring before cancelling");

    wraplock::xfer x = {
      .owner = _self, // todo - check whether this should show as redeem_act.beneficiary
      .quantity = extended_asset(redeem_act.quantity.quantity, redeem_act.quantity.contract),
      .beneficiary = redeem_act.owner
    };

    // return to redeem_act.owner so can be withdrawn from wraplock
    wraplock::emitxfer_action act(_self, permission_level{_self, "active"_n});
    act.send(x);

}

void wraplock::cancela(const name& prover, const bridge::heavyproof blockproof, const bridge::actionproof actionproof)
{
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    check(current_time_point().sec_since_epoch() > blockproof.blocktoprove.block.header.timestamp.to_time_point().sec_since_epoch() + 900, "must wait 15 minutes to cancel");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _heavy_proof.get_or_create(_self, _heavy_proof_obj);
    p.hp = blockproof;
    _heavy_proof.set(p, _self);
    wraplock::heavyproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _cancel(prover, actionproof);
}

void wraplock::cancelb(const name& prover, const bridge::lightproof blockproof, const bridge::actionproof actionproof)
{
    require_auth(prover);

    check(global_config.exists(), "contract must be initialized first");
    auto global = global_config.get();

    check(global.enabled == true, "contract has been disabled");

    check(blockproof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");

    check(current_time_point().sec_since_epoch() > blockproof.header.timestamp.to_time_point().sec_since_epoch() + 900, "must wait 15 minutes to cancel");

    // check proof against bridge
    // will fail tx if prove is invalid
    auto p = _light_proof.get_or_create(_self, _light_proof_obj);
    p.lp = blockproof;
    _light_proof.set(p, _self);
    wraplock::lightproof_action checkproof_act(global.bridge_contract, permission_level{_self, "active"_n});
    checkproof_act.send(_self, actionproof);

    _cancel(prover, actionproof);
}


/*void wraplock::clear()
{ 
  require_auth( _self );

  check(global_config.exists(), "contract must be initialized first");

  // if (global_config.exists()) global_config.remove();

  auto contractrow = _contractmappingtable.end();
  while ( _contractmappingtable.begin() != _contractmappingtable.end() ) {
      contractrow--;
      reserves _reservestable( _self, contractrow->native_token_contract.value );
      while (_reservestable.begin() != _reservestable.end()) {
        auto itr = _reservestable.end();
        itr--;
        _reservestable.erase(itr);
      }
      _contractmappingtable.erase(contractrow);
  }

  while (_processedtable.begin() != _processedtable.end()) {
    auto itr = _processedtable.end();
    itr--;
    _processedtable.erase(itr);
  }

}*/

} /// namespace eosio

