import { Router } from 'express';
import { tokenMiddleware } from '../middlewares/token.js';
import { authController, fidoAuthController } from '../controllers/auth.ctrl.js';

const router = Router();

router.post('/login', authController.login);
router.get('/me', tokenMiddleware.check, authController.me);


router.post('/publickey/challenge', fidoAuthController.publicKeyChallenge);
router.post('/publickey', tokenMiddleware.check, fidoAuthController.publicKey, fidoAuthController.ok, fidoAuthController.error);
router.get('/publickey/credential', tokenMiddleware.check, fidoAuthController.getCredential);



export default router;