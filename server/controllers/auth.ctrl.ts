import passport from "passport";
import WebAuthnStrategy from 'passport-fido2-webauthn'
import SessionChallengeStore from 'passport-fido2-webauthn'

import { userService } from '../services/users.serv.js';
import { userModel } from '../models/users.model.js';
import { credentialsModel } from '../models/credentials.model.js';


const store = new SessionChallengeStore.SessionChallengeStore();

passport.use(new WebAuthnStrategy({ store: store },
  async function verify(userId, userHandle, cb) {
    const credential = await credentialsModel.read({ userId: userId })
    if (credential.status == 0) { return cb(null, false, { message: 'Invalid key. '}); }

    const publicKey = credential.credential.publicKey
    const user = await userModel.read({ userId: userId })

    return cb(null, user.user, publicKey);
  },

  async function register(userId, userEmail, publicKey, cb) {
    const isAvailable = await userService.checkAvailableUser({ userId: userId, userEmail: userEmail })
    const getUser = await userModel.read({ userId, userEmail })
    const isDuplicate = getUser.status


    if (isAvailable == 0 || isDuplicate != 0) {
        return cb('err in register');
    }

    const data = await userModel.create({ 
        userId: userId, 
        userPasswordHash: '', 
        userEmail: userEmail ,
        provider: "fido2"
    })

    const isGrantAuthorization: any = await userModel.update({ userId: userId, auth: 1 });
    const getJwtToken = await userService.grantToken({ userId: userId });
    const createdToken = getJwtToken.userJwtToken

    if (isGrantAuthorization.status == 0) {
        return cb('err in register');
    }

    const createCredential = await credentialsModel.create({
        userId: userId,
        publicKey: publicKey
    })

    return cb(null, createdToken);
  }
));


const authController = {
    login: async function (req, res) {
        try {
            const userId = Buffer.from(req.body.user_id, "base64").toString('utf8');
            const userPassword = Buffer.from(req.body.user_pw, "base64").toString('utf8');
        
            const userInfo = await userModel.read({ userId: userId })
            const result = await userService.comparePassword({ 
                userPassword: userPassword,
                userPasswordHash: userInfo.user.userPassword
            })

            if (userInfo.user.userAuthLevel == 0) {
                return res.status(401).json({status: -1})
            }

            if (result.status == 0) {
                return res.status(401).json({status: -1})
            }

            const getJwtToken = await userService.grantToken({ userId: userId });
            const createdToken = getJwtToken.userJwtToken

            if (getJwtToken.status == 0) {
                return res.status(401).json({status: -1})
            }

            res.status(200).json({status:1, token: createdToken})

        } catch (error) {
            res.status(401).json({status:0})
        }
    },


    me: async function (req, res) {
        const token = req.headers['x-access-token'];
        const data = await userService.transformTokentoUserid({ token: token })
        res.status(200).json({status:1, user_id:data})
    }
}

const fidoAuthController = {
    login: async function (req, res) {
        try {

      

        } catch (error) {
            res.status(401).json({status:0})
        }
    },

}

export { authController }