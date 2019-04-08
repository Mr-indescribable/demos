package src.test;

import java.io.InputStream;

import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaClient;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;


public class Test
{
	public static void main(String[] args){
		String jschRoot = "src/test/";
		SchemaLoader schemaLoader = SchemaLoader.builder()
						.schemaClient(SchemaClient.classPathAwareClient())
						.resolutionScope("classpath://" + jschRoot)
						.build();

		InputStream inStream = Test.class
						.getClassLoader()
						.getResourceAsStream(jschRoot + "/schema.json");

		JSONObject rawSchema = new JSONObject( new JSONTokener(inStream) );
		Schema schema = schemaLoader.load(rawSchema);

		String jstrToValidate = "{\"a\": 1}";

		schema.validate( new JSONObject(jstrToValidate) );
	}
}
