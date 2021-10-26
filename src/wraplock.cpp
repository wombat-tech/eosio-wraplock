#include <wraplock.hpp>

namespace eosio {


//fetches proof from the bridge contract
token::validproof token::get_proof(const uint64_t proof_id){

  auto p = _proofstable.find(proof_id);

  check(p != _proofstable.end(), "proof not found");

  return *p;

}


//adds a proof to the list of processed proofs (throws an exception if proof already exists)
void token::add_or_assert(const validproof& proof, const name& payer){

    auto pid_index = _processedtable.get_index<"digest"_n>();

    auto p_itr = pid_index.find(proof.receipt_digest);

    check(p_itr == pid_index.end(), "action already proved");

    _processedtable.emplace( payer, [&]( auto& s ) {
        s.id = _processedtable.available_primary_key();
        s.receipt_digest = proof.receipt_digest;
    });

}

void token::init(const checksum256& chain_id, const name& native_token_contract, const checksum256& paired_chain_id, const name& paired_wraptoken_contract)
{
    require_auth( _self );

    auto global = global_config.get_or_create(_self, globalrow);
    global.chain_id = chain_id;
    global.native_token_contract = native_token_contract;
    global.paired_chain_id = paired_chain_id;
    global.paired_wraptoken_contract = paired_wraptoken_contract;
    global_config.set(global, _self);

}

//locks a token amount in the reserve for an interchain transfer
void token::lock(const name& owner,  const extended_asset& quantity, const name& beneficiary){

  require_auth(owner);

  check(quantity.contract != _self, "cannot lock wrapped tokens");


  sub_external_balance( owner, quantity );
  add_reserve( quantity );

  token::xfer x = {
    .owner = owner,
    .quantity = quantity,
    .beneficiary = beneficiary
  };

  action act(
    permission_level{_self, "active"_n},
    _self, "emitxfer"_n,
    std::make_tuple(x)
  );
  act.send();

}

//emits an xfer receipt to serve as proof in interchain transfers
void token::emitxfer(const token::xfer& xfer){
 
 require_auth(_self);

}

void token::sub_reserve( const extended_asset& value ){

   //reserves res_acnts( get_self(), _self.value );

   const auto& res = _reservestable.get( value.quantity.symbol.code().raw(), "no balance object found" );
   check( res.balance.quantity.amount >= value.quantity.amount, "overdrawn balance" );

   _reservestable.modify( res, _self, [&]( auto& a ) {
         a.balance -= value;
      });
}

void token::add_reserve(const extended_asset& value){

   //reserves res_acnts( get_self(), _self.value );

   auto res = _reservestable.find( value.quantity.symbol.code().raw() );
   if( res == _reservestable.end() ) {
      _reservestable.emplace( _self, [&]( auto& a ){
        a.balance = value;
      });
   } else {
      _reservestable.modify( res, _self, [&]( auto& a ) {
        a.balance += value;
      });
   }

}

void token::sub_external_balance( const name& owner, const extended_asset& value ){

   extaccounts from_acnts( get_self(), owner.value );

   const auto& from = from_acnts.get( value.quantity.symbol.code().raw(), "no balance object found" );
   check( from.balance.quantity.amount >= value.quantity.amount, "overdrawn balance" );

   from_acnts.modify( from, owner, [&]( auto& a ) {
         a.balance -= value;
      });
}

void token::add_external_balance( const name& owner, const extended_asset& value, const name& ram_payer ){

   extaccounts to_acnts( get_self(), owner.value );
   auto to = to_acnts.find( value.quantity.symbol.code().raw() );
   if( to == to_acnts.end() ) {
      to_acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance = value;
      });
   } else {
      to_acnts.modify( to, same_payer, [&]( auto& a ) {
        a.balance += value;
      });
   }

}

void token::open( const name& owner, const symbol& symbol, const name& ram_payer )
{
   require_auth( ram_payer );

   check( is_account( owner ), "owner account does not exist" );

   auto global = global_config.get();
   add_external_balance(owner, extended_asset(asset{0, symbol}, global.native_token_contract), ram_payer);

}

void token::close( const name& owner, const symbol& symbol )
{
   require_auth( owner );

}

void token::deposit(name from, name to, asset quantity, string memo)
{ 

    print("transfer ", name{from}, " ",  name{to}, " ", quantity, "\n");
    print("sender: ", get_sender(), "\n");
    
    auto global = global_config.get();
    check(get_sender() == global.native_token_contract, "transfer not permitted from unauthorised token contract");

    extended_asset xquantity = extended_asset(quantity, global.native_token_contract);

    //if incoming transfer
    if (from == "eosio.stake"_n) return ; //ignore unstaking transfers
    else if (to == get_self() && from != get_self()){
      //ignore outbound transfers from this contract, as well as inbound transfers of tokens internal to this contract
      //otherwise, means it's a deposit of external token from user
      add_external_balance(from, xquantity, from);

    }

}

//withdraw tokens (requires a proof of redemption)
void token::withdraw(const name& caller, const uint64_t proof_id){

    // todo - add ability to withdraw without proof_id, or move that into unlock

    require_auth( caller );

    token::validproof proof = get_proof(proof_id);

    token::xfer redeem_act = unpack<token::xfer>(proof.action.data);

    auto global = global_config.get();
    check(proof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");
    check(proof.action.account == global.paired_wraptoken_contract, "proof account does not match paired account");
   
    add_or_assert(proof, caller);

    check(proof.action.name == "emitxfer"_n, "must provide proof of token retiring before issuing");

    sub_reserve(redeem_act.quantity);
    
    action act(
      permission_level{_self, "active"_n},
      redeem_act.quantity.contract, "transfer"_n,
      std::make_tuple(_self, redeem_act.beneficiary, redeem_act.quantity.quantity, ""_n )
    );
    act.send();

}

void token::clear()
{ 

  // todo - tidy this so all data is cleared (iterate over scopes)

  // if (global_config.exists()) global_config.remove();

  accounts a_table( get_self(), "genesis11111"_n.value);
  extaccounts e_table( get_self(), "genesis11111"_n.value);

  stats s1_table( get_self(), symbol_code("UTX").raw());
  stats s2_table( get_self(), symbol_code("OOO").raw());

  while (s1_table.begin() != s1_table.end()) {
    auto itr = s1_table.end();
    itr--;
    s1_table.erase(itr);
  }

  while (s2_table.begin() != s2_table.end()) {
    auto itr = s2_table.end();
    itr--;
    s2_table.erase(itr);
  }

  while (a_table.begin() != a_table.end()) {
    auto itr = a_table.end();
    itr--;
    a_table.erase(itr);
  }

  while (e_table.begin() != e_table.end()) {
    auto itr = e_table.end();
    itr--;
    e_table.erase(itr);
  }

  while (_reservestable.begin() != _reservestable.end()) {
    auto itr = _reservestable.end();
    itr--;
    _reservestable.erase(itr);
  }

  while (_proofstable.begin() != _proofstable.end()) {
    auto itr = _proofstable.end();
    itr--;
    _proofstable.erase(itr);
  }

  while (_proofstable.begin() != _proofstable.end()) {
    auto itr = _proofstable.end();
    itr--;
    _proofstable.erase(itr);
  }

/*
accounts

proofstable

stats
*/
}

} /// namespace eosio

