import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import ValidateForm from 'src/app/helpers/validateform';
import { AuthService } from 'src/app/services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

  type: string = "password";
  isText: boolean = false;
  eyeIcon: string = "fa-eye-slash";
  loginForm!: FormGroup;

  constructor(private fb: FormBuilder, private auth: AuthService, private router: Router) { }

  ngOnInit(): void {
    this.loginForm = this.fb.group({
      username: ['', Validators.required],
      password: ['', Validators.required]
    })
  }

  hideShowPass() {
    this.isText = !this.isText;
    this.isText ? this.eyeIcon = 'fa-eye' : this.eyeIcon = 'fa-eye-slash';
    this.isText ? this.type = 'text' : this.type = 'password';
  }

  onLogin() {
    if(this.loginForm.valid) {
      // send the object to DB
      console.log(this.loginForm.value)
      this.auth.login(this.loginForm.value)
        .subscribe({
          next: (res) => {
            alert(res.message);
            this.loginForm.reset();
            this.router.navigate(['dashboard'])
          },
          error:(err) => {
            alert(err?.error.message)
          }
        })
    } else {
      // throw error using toaster and with required field
      ValidateForm.validateAllFormFields(this.loginForm);
      alert("Your form is invalid")
    }
  }


}
