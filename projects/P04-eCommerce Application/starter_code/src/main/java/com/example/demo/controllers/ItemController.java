package com.example.demo.controllers;

import java.util.List;

import com.example.demo.model.requests.ItemRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.repositories.ItemRepository;

import javax.transaction.Transactional;

@RestController
@RequestMapping("/api/item")
public class ItemController {

	@Autowired
	private ItemRepository itemRepository;
	
	@GetMapping
	public ResponseEntity<List<Item>> getItems() {
		return ResponseEntity.ok(itemRepository.findAll());
	}
	
	@GetMapping("/{id}")
	@Transactional
	public ResponseEntity<Item> getItemById(@PathVariable Long id) {
		return ResponseEntity.of(itemRepository.findById(id));
	}
	
	@GetMapping("/name/{name}")
	@Transactional
	public ResponseEntity<List<Item>> getItemsByName(@PathVariable String name) {
		List<Item> items = itemRepository.findByName(name);
		return items == null || items.isEmpty() ? ResponseEntity.notFound().build()
				: ResponseEntity.ok(items);
			
	}

	@PostMapping("/create")
	@Transactional
	public ResponseEntity<Item> createItem(@RequestBody ItemRequest itemRequest){
		Item item = new Item();
		item.setName(itemRequest.getName());
		item.setPrice(itemRequest.getPrice());
		item.setDescription(itemRequest.getDescription());

		item = itemRepository.save(item);
		return item == null? ResponseEntity.badRequest().build()
				:ResponseEntity.ok(item);
	}
	
}
