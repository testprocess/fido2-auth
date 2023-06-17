import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from "typeorm";

@Entity({ name: "credentials" })
export class Credentials {
    @PrimaryGeneratedColumn('increment')
    idx: number;

    @Column({ type: "varchar", length: 20 })
    userId: string;

    @Column({ type: "varchar", length: 500 })
    publicKey: string;

    @Column({ type: "varchar", length: 500 })
    credentialId: string;
    

}