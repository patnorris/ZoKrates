extern crate serde_json;
extern crate zokrates_core;
extern crate zokrates_field;
#[macro_use]
extern crate serde_derive;

#[macro_use]
mod utils;

zokrates_test! {
    add,
    assert_one,
}
