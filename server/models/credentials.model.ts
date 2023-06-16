import { MySQLConnect, AppDataSource } from '../databases/db.js'

import { Credentials } from "../databases/entity/Credentials.js";


const credentialsModel = {
    create: async function ({ userId, publicKey }) {
        try {
            const credentialValues = new Credentials()
            credentialValues.userId = userId
            credentialValues.publicKey = publicKey
    
            const userRepository = AppDataSource.getRepository(Credentials);
            await userRepository.save(credentialValues)
            return { status: 1 }
    
        } catch (err) {
            console.log(err)
            return { status: 0 }
        }
    },
    
    read: async function ({ userId }: any) {
        try {
            const credentialRepository = AppDataSource.getRepository(Credentials);
            const getCredential = await credentialRepository
                .createQueryBuilder("user")
                .where("user.userId = :id", { id: userId })
                .getOne()
    
            const status = getCredential == null ? 0 : 1
            return { status: status, credential: getCredential }
        } catch (err) {
            console.log(err)
            throw Error(err)
        }
    }

}

export { credentialsModel }