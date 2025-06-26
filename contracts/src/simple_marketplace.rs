//! Simple Marketplace Contract for testing
use wasm_bindgen::prelude::*;
use serde_json;

#[wasm_bindgen]
pub struct SimpleMarketplace {
    item_count: u32,
}

#[wasm_bindgen]
impl SimpleMarketplace {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SimpleMarketplace {
        SimpleMarketplace {
            item_count: 0,
        }
    }

    #[wasm_bindgen]
    pub fn list_item(&mut self, seller: &str, title: &str, price: f64) -> String {
        self.item_count += 1;
        
        serde_json::json!({
            "success": true,
            "item_id": self.item_count,
            "seller": seller,
            "title": title,
            "price": price,
            "status": "listed"
        }).to_string()
    }

    #[wasm_bindgen]
    pub fn get_items(&self) -> String {
        serde_json::json!({
            "success": true,
            "items": [
                {
                    "id": 1,
                    "title": "ZHTP Node Hardware",
                    "price": 500.0,
                    "seller": "validator-node-1",
                    "status": "available"
                }
            ],
            "count": 1
        }).to_string()
    }
}
