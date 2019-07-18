package test.springhw.ctrller1;

import org.json.JSONObject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMethod;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;


@RestController
public class RootController1 {

    @RequestMapping(value="/springhw1", method=RequestMethod.GET)
	public ResponseEntity<String> springhw(){
		JSONObject rjson;
		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> resp;

		rjson = new JSONObject();
		rjson.put("content", "hello world");
		headers.add("Content-Type", "application/json;charset=UTF-8");

		resp = new ResponseEntity<String>(
			rjson.toString(), headers, HttpStatus.OK
		);

        return resp;
    }

}
