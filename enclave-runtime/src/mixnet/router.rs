pub use route_recognizer::{Router, Params};

/*use sgx_tstd as std;


use codec::{alloc::string::String};
use std::{
	string::ToString,
}; */
pub fn load_all_routes() -> Router<()> {
    let mut router = Router::new();
    router.add("/", index());
    /*
    router.add("/tom", "Tom".to_string());
    router.add("/wycats", "Yehuda".to_string());
    */
    router
}

pub fn index(){

}