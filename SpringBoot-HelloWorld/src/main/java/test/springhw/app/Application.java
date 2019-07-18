package test.springhw.app;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import test.springhw.ctrller1.RootController1;
import test.springhw.ctrller2.RootController2;


//@SpringBootApplication(scanBasePackages="test.springhw.ctrller")
@SpringBootApplication
@ComponentScan(basePackageClasses = {
	RootController1.class,
	RootController2.class,
})
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
