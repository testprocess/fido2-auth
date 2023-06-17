import React, { useState, useEffect } from "react";
import Cookies from 'js-cookie'
import { base64url } from "../utils/base64url";



function Main() {
    const [isLogin, setLoginStatus] = useState(0);

    const checkLogin = () => {
        let token = Cookies.get("user")
        try {
            let decoded = JSON.parse(atob(token.split('.')[1]));
            return {
                isVaild: 1,
                decoded: decoded
            }
        } catch (error) {
            return {
                isVaild: 0
            }
        }
    }

    const sp = () => {
        const userId = 'dddsw'

        return fetch('/api/auth/publickey/challenge', {
            method: 'POST',
            headers: {
              'Accept': 'application/json'
            },
            body: JSON.stringify({
                name: userId,
                username: userId,
            }),
          })
          .then(function(response) {
            return response.json();
          })
          .then(function(json) {
            return navigator.credentials.create({
              publicKey: {
                rp: {
                  name: 'fido2'
                },
                user: {
                  id: new TextEncoder().encode(userId),
                  name: userId,
                  displayName: userId
                },
                challenge: new TextEncoder().encode(json.challenge),
                pubKeyCredParams: [
                  {
                    type: 'public-key',
                    alg: -7
                  }
                ],
                authenticatorSelection: {
                  userVerification: 'discouraged',
                  //authenticatorAttachment: "platform",
                  residentKey: 'required'
                }
              }
            });
          })
          .then(function(credential: any) {
            const rawId = base64url.encode(credential.rawId);
            const clientDataJSON = base64url.encode(credential.response.clientDataJSON);
            const attestationObject = base64url.encode(credential.response.attestationObject);
            
            let body = {
                response: {
                    rawId: rawId,
                    clientDataJSON: clientDataJSON,
                    attestationObject: attestationObject,
                    transports: undefined
                }
            };

            console.log(body)
            

            if (credential.response.getTransports) {
              body.response.transports = credential.response.getTransports();
            }
            
            return fetch('/api/auth/publickey', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'x-access-token': Cookies.get("user")
              },
              body: JSON.stringify(body)
            });
          })
          .then(function(response) {
            return response.json();
          })
          .then(function(json) {
            console.log(json)
            //window.location.href = json.location;
          })
          .catch(function(error) {
            console.log(error);
          });
    }

    useEffect(() => {
        let loginStatus = checkLogin()
        setLoginStatus(loginStatus.isVaild)
    }, []);


    return (
        <header className="bg-white py-5">
            <div className="container-fluid px-5 pt-4 pb-2">
                <div className="row gx-5 justify-content-center">
                    <div className="col-lg-7">
                        <div className="text-center mt-5">
                            <h1 className="display-5 fw-bolder text-dark font-weight-lg mb-2">FIDO2</h1>
                            <p className="font-weight-sm mb-4 mt-3">비밀번호 없는 로그인을 구현할 수 있어요</p>
                        </div>
                        <button onClick={sp}>df</button>
                        <ButtonBox isLogin={isLogin}></ButtonBox>

                    </div>
                </div>
            </div>
        </header>
    );
}


function ButtonBox({ isLogin }) {
    const handleClickSignup = () => {
        location.href = '/auth/signup'
    }

    const handleClickLogin = () => {
        location.href = '/auth/login'
    }

    const handleClickLogout = () => {
        document.cookie = 'user=; expires=Thu, 01 Jan 1999 00:00:10 GMT;';
        location.href = '/'
    }

    if (isLogin) {
        return (
            <div className="d-grid gap-3 d-sm-flex justify-content-sm-center" id="login_box">
                <button className="btn btn-red font-weight-md btn-lg px-4 " onClick={handleClickLogout}><i className="fas fa-user-minus"></i> 로그아웃</button>
            </div>
        );
    }

    return (
        <div className="d-grid gap-3 d-sm-flex justify-content-sm-center" id="login_box">
            <button className="btn btn-blue font-weight-md btn-lg px-4 btn-rounded" onClick={handleClickSignup}><i className="fas fa-user-plus"></i> 가입</button>
            <button className="btn btn-light font-weight-md btn-lg px-4 me-sm-3 btn-rounded" onClick={handleClickLogin}><i className="fas fa-sign-in-alt"></i> 로그인</button>
        </div>
    );
}
  
export default Main;