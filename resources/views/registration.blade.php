<!DOCTYPE html>
<html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Login page</title>

        <style>
            body {
                font-family: Arial, Helvetica, sans-serif;
                height: 600px;
                width: 400px;
                align-items: center;
                position: absolute;
                left: 50%;
                top: 50%;
                transform: translate(-50%, -50%);
                background-color: #f1f1f1;
            }

            form {
                border: 3px solid #fff;
                background-color: #fff;
            }

            input[type="text"],
            input[type="password"] {
                width: 100%;
                padding: 12px 20px;
                margin: 8px 0;
                display: inline-block;
                border: 1px solid #ccc;
                box-sizing: border-box;
            }

            button {
                border-radius: 6px;
                background-color: #04aa6d;
                color: white;
                padding: 14px 20px;
                margin: 8px 0;
                border: none;
                cursor: pointer;
                width: 100%;
                transition-duration: 0.4s;
            }

            .forgotbtn:hover {
                opacity: 0.8;
            }

            .cancelbtn:hover {
                opacity: 0.8;
            }

            .logButton {
                display: inline-block;
                border-radius: 4px;
                border: none;
                text-align: center;
                padding: 20px;
                font-size: 24px;
                transition: all 0.5s;
                cursor: pointer;
                margin: 5px;
            }

            .logButton span {
                cursor: pointer;
                display: inline-block;
                position: relative;
                transition: 0.5s;
            }

            .logButton span:after {
                content: "\00bb";
                position: absolute;
                opacity: 0;
                top: 0;
                right: -20px;
                transition: 0.5s;
            }

            .logButton:hover span {
                padding-right: 25px;
            }

            .logButton:hover span:after {
                opacity: 1;
                right: 0;
            }

            .cancelbtn {
                width: auto;
                padding: 10px 18px;
                background-color: #f44336;
            }

            .forgotbtn {
                width: auto;
                padding: 10px 18px;
                background-color: #5c5c5c;
                float: right;
                padding-top: 16px;
            }

            .imgcontainer {
                text-align: center;
                margin: 24px 0 12px 0;
            }

            img.avatar {
                width: 40%;
                border-radius: 50%;
            }

            .container {
                padding: 16px;
            }

            /* Change styles for span and cancel button on extra small screens */
            @media screen and (max-width: 300px) {
                span.psw {
                    display: block;
                    float: none;
                }
                .cancelbtn {
                    width: 100%;
                }
            }
        </style>
    </head>
    <body>
        <h2>Register Form</h2>

        <form action="/api/registration" method="post">
            <div class="container">
                <label for="user_name"><b>Username</b></label>
                <input
                    type="text"
                    placeholder="Enter Username"
                    name="name"
                    required
                />

                <label for="email"><b>Email</b></label>
                <input
                    type="text"
                    placeholder="Enter Email"
                    name="email"
                    required
                />

                <label for="phone"><b>Phone</b></label>
                <input
                    type="text"
                    placeholder="Enter Phone"
                    name="phone"
                    required
                />

                <label for="password"><b>Password</b></label>
                <input
                    type="password"
                    placeholder="Enter Password"
                    name="password"
                    required
                />

                <button class="logButton" style="vertical-align: middle">
                    <span>Register</span>
                </button>
                <label>
                    <input
                        type="checkbox"
                        checked="checked"
                        name="remember_token"
                    />
                    Remember me
                </label>
            </div>

            <div class="container" style="background-color: #f1f1f1">
                <button type="button" class="cancelbtn">Cancel</button>
                <button type="button" class="forgotbtn">
                    Forgot password?
                </button>
            </div>
        </form>
    </body>
</html>
