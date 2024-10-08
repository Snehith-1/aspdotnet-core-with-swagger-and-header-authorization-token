import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule], 
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent implements OnInit {


  users:any;
  constructor(private http: HttpClient) {

  }
  ngOnInit(): void {
    this.getAllusers();
  }

  getAllusers() {
    debugger;
    this.http.get('https://localhost:44345/api/Auth/GetUsers').subscribe((res:any) => {
      this.users = res.users;
    } , error => {
      alert("Token Expired !")
    })
  }

}
