package controller;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;

@Controller
public class AuthController {
    @GetMapping("/")
    public ModelAndView home(){
        return new ModelAndView("/home");
    }
    @GetMapping("/user")
    public ModelAndView user(Principal principal){
        System.out.println(principal.getName());
        return new ModelAndView("/user");
    }
    @GetMapping("/admin")
    public ModelAndView admin(){
//        SecurityContext context = SecurityContextHolder.getContext();
//        System.out.println(context.getAuthentication().getName());
        return new ModelAndView("/admin");
    }
    @GetMapping("/link1")
    String link1(){
        return "/link/link1";
    }
    @GetMapping("/link2")
    String link2(){
        return "/link/link2";
    }
}
