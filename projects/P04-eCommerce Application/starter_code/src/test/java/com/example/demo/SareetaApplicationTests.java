package com.example.demo;

import com.example.demo.controllers.CartController;
import com.example.demo.controllers.ItemController;
import com.example.demo.controllers.OrderController;
import com.example.demo.controllers.UserController;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.requests.CreateUserRequest;
import com.example.demo.model.requests.ItemRequest;
import com.example.demo.model.requests.ModifyCartRequest;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

//@RunWith(SpringRunner.class)
@SpringBootTest()
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SareetaApplicationTests {

	/**
	@Test
	public void contextLoads() {
	}
	*/

	@Autowired
	private UserController userController;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
	private ItemController itemController;
	@Autowired
	private CartController cartController;
	@Autowired
	private OrderController orderController;

	private final Logger logger = LoggerFactory.getLogger(SareetaApplicationTests.class);

	//testing data
	private static String uname;
	private static String pwd;
	private static String cpwd;
	private static String cpwd_bad;
	private static String pwd_bad;

	public static String itemName;
	public static int itemPrice;
	public static String itemDes;

	private static ResponseEntity<User> res;
	private static User usr;
	private static CreateUserRequest userRequest;

	private static ItemRequest itemRequest;
	private static ResponseEntity<Item> resItem;
	private static Item item;

	private static ModifyCartRequest cartRequest;
	private static Cart cart;

    @BeforeAll
	private static void setup(){
		 uname="userone";
		 pwd ="pass123";
		 cpwd=pwd;

		 cpwd_bad="p123"; //not matching pwd
		 pwd_bad="pass"; //not enough length
		 userRequest = new CreateUserRequest();

		 itemName="iPhone 13";
		 itemPrice =599;
		 itemDes ="New iPhone";
		 itemRequest = new ItemRequest();

		 cartRequest=new ModifyCartRequest();
	}

	//***good case of creating user***//
	@Test
	@Order(1)
	public void testCreateUser_sunny(){
		logger.debug("test 1: testCreateUser_sunny");
		//create user
		userRequest.setUsername(uname);
		userRequest.setPassword(pwd);
		userRequest.setConfirmedPasswd(cpwd);

		res = userController.createUser(userRequest);
		Assertions.assertNotNull(res);
		Assertions.assertEquals(200,res.getStatusCode().value());
		usr=res.getBody();
		Assertions.assertNotNull(usr);

		Assertions.assertEquals(uname,usr.getUsername());
		//assert raw passwd (in request) matches encoded passwd (as the member of user)
		Assertions.assertTrue(bCryptPasswordEncoder.matches(userRequest.getPassword(), usr.getPassword()));


		//get user by id
		res = userController.findById(usr.getId());
		Assertions.assertNotNull(res);
		Assertions.assertEquals(200,res.getStatusCode().value());
		User usr_find_byId = res.getBody();
		Assertions.assertEquals(usr.getUsername(),usr_find_byId.getUsername());
		Assertions.assertEquals(usr.getPassword(), usr_find_byId.getPassword());

		//get user by name
		res = userController.findByUserName(usr.getUsername());
		Assertions.assertNotNull(res);
		Assertions.assertEquals(200,res.getStatusCode().value());
		User usr_find_byName = res.getBody();
		Assertions.assertEquals(usr.getId(),usr_find_byName.getId());
		Assertions.assertEquals(usr.getPassword(), usr_find_byName.getPassword());
	}

	//***bad case of creating user***//
	@Test
	@Order(2)
	public void testCreateUser_rainy(){
		logger.debug("test 2: testCreateUser_rainy");
		//pwd not matching
		userRequest.setUsername(uname+"rainy1"); //different user name from other test
		userRequest.setPassword(pwd);
		userRequest.setConfirmedPasswd(cpwd_bad);
		res = userController.createUser(userRequest);
		Assertions.assertNotNull(res);
		Assertions.assertEquals(400,res.getStatusCode().value());

		//pwd not enough length
		userRequest.setUsername(uname+"rainy2"); //different user name from other test
		userRequest.setPassword(pwd_bad);
		userRequest.setConfirmedPasswd(pwd_bad);
		res = userController.createUser(userRequest);
		Assertions.assertNotNull(res);
		Assertions.assertEquals(400,res.getStatusCode().value());

	}

	//**test for item//
	@Test
	@Order(3)
	public void testItem(){
		logger.debug("test 3: testItem");
		//create item
		itemRequest.setName(itemName);
		itemRequest.setPrice(new BigDecimal(itemPrice));
		itemRequest.setDescription(itemDes);

		resItem = itemController.createItem(itemRequest);
		Assertions.assertNotNull(resItem);
		item = resItem.getBody();
		Assertions.assertNotNull(item);

		//assert name, price and description
		Assertions.assertEquals(itemName, item.getName());
		Assertions.assertEquals(itemDes, item.getDescription());
		Assertions.assertEquals(new BigDecimal(itemPrice),item.getPrice());

		//assert only 3 item. two from initialization, 1 just added
		ResponseEntity<List<Item>> resItems=itemController.getItems();
		//we created 1 here, but at the start 2 were already created by data.sql
		Assertions.assertEquals(3, resItems.getBody().stream().count());

		Item itemFromGet;
		//assert getById
		resItem =itemController.getItemById(item.getId());
		Assertions.assertNotNull(resItem);
		itemFromGet = resItem.getBody();
		Assertions.assertTrue(itemFromGet.equals(item));

		//assert getByName
		resItems =itemController.getItemsByName(item.getName());
		Assertions.assertNotNull(resItems);
		Optional<Item> oi = resItems.getBody().stream().findFirst();
		Assertions.assertTrue(oi.isPresent());
		itemFromGet=oi.get();
		Assertions.assertTrue(itemFromGet.equals(item));

	}

	@Test
	@Order(4)
	//test Cart
	public void testCartAndOrder(){
		logger.debug("Test 4: Cart");
		//previous tests had created user and item in DB, we can use them here directly
		//***test adding item to cart
		cartRequest.setUsername(uname);
		cartRequest.setItemId(item.getId());
		cartRequest.setQuantity(1);
		cartController.addTocart(cartRequest);

		//Refresh user (in turn the cart of this user) from DB
		res = userController.findById(usr.getId());
		Assertions.assertNotNull(res);
		Assertions.assertEquals(200,res.getStatusCode().value());
		usr = res.getBody();

		cart=usr.getCart();
		Assertions.assertNotNull(cart);

		//Assert Cart total is as expected
		Assertions.assertEquals(0,item.getPrice().compareTo(cart.getTotal()));

		//Assert only one item in the item list, and it is the one we just added
		List<Item> itemLs = cart.getItems();
		Assertions.assertNotNull(itemLs);

		Assertions.assertEquals(1,itemLs.stream().count());
		//Optional<Item> oi=itemLs.stream().findFirst();
		//Assertions.assertTrue(oi.isPresent());
		//Item itemFromCart=oi.get();
		Item itemFromCart=itemLs.get(0);
		Assertions.assertTrue(itemFromCart.equals(item));

		//before removing item, testing the order
		testOrder_sunny();

		//**testing removing item from cart
		//Same cartRequest as above, it is already set
		cartController.removeFromcart(cartRequest);
		//Refresh user (in turn the cart of this user) from DB
		res = userController.findById(usr.getId());
		Assertions.assertNotNull(res);
		Assertions.assertEquals(200,res.getStatusCode().value());
		usr = res.getBody();
		cart=usr.getCart();
		Assertions.assertNotNull(cart);

		//Assert Cart total is as expected, it should be 0
		Assertions.assertEquals(0,new BigDecimal(0).compareTo(cart.getTotal()));
		//Assert 0 item in the item list
		 itemLs = cart.getItems();
		Assertions.assertNotNull(itemLs);

		Assertions.assertEquals(0,itemLs.stream().count());

	}

	//not a seperated test case, called by testCartAndOrder() after one item added to order
	private void testOrder_sunny(){
		ResponseEntity<UserOrder> resOrder = orderController.submit(uname);
		Assertions.assertNotNull(resOrder);
		Assertions.assertEquals(200,resOrder.getStatusCode().value());
		UserOrder ord=resOrder.getBody();
		Assertions.assertNotNull(ord);

		//Assert user of order
		Assertions.assertEquals(ord.getUser().getUsername(),uname);
		//Assert order total
		Assertions.assertEquals(0,ord.getTotal().compareTo(item.getPrice()));
		//Assert order items
		List<Item> itemLs = ord.getItems();
		Assertions.assertNotNull(itemLs);
		Assertions.assertEquals(1,itemLs.stream().count());
		Item itemFromOrder = itemLs.get(0);
		Assertions.assertTrue(itemFromOrder.equals(item));

	}

	private void testOrder_rainy(){
		ResponseEntity<UserOrder> resOrder = orderController.submit("user_wrong"); //order with wrong user name
		Assertions.assertNotNull(resOrder);
		Assertions.assertEquals(ResponseEntity.notFound().build().getStatusCode(),resOrder.getStatusCode().value());
	}

}
