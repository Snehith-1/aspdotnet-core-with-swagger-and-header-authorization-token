import { HttpClient } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { Router } from '@angular/router';


@Component({
  selector: 'app-login',
  standalone: true,
  imports: [FormsModule, HttpClientModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent {
  loginObj: Login;

  constructor(private http: HttpClient,private router: Router ) {
    this.loginObj = new Login();
  }

  onLogin() {
    debugger;
    if(this.loginObj.user_code!= null && this.loginObj.user_password)
      {
    this.http.post('https://localhost:44345/api/Auth/Token', this.loginObj).subscribe((res:any)=>{
      if(res) {
        alert("Login Success");
        localStorage.setItem('angular17token', res.token)
        this.router.navigateByUrl('/dashboard')
      } else {
        alert(res.message)

      }
    })
  }
  else
  {
    alert("Enter User Details !!")
  }
  }
}

export class Login { 
   user_code: string;
    user_password: string;
    constructor() {
      this.user_code = '';
      this.user_password = '';
    } 
}
