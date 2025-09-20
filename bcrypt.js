const bcrypt = require('bcrypt');
const { log } = require('console');

async function hashPassword(plainPassword){
    const saltRounds = 10;
    const hashed = await bcrypt.hash(plainPassword, saltRounds);
    console.log("Mot de passe haché :",hashed);
}

async function checkPassword(plainPassword, hashedPassword){
    const match = await bcrypt.compare(plainPassword, hashedPassword);
    if (match){
        console.log("Mot de passe correct");
    } else {
        console.log("Mot de passe incorrect");
        
    }
}


hashPassword("user")
//const hash = "$2b$15$4oy/rE5IaNEePZQPjT3mgOejZ006dV37a2OUqt/yQTSk/rzATanFC";
//checkPassword("12/07/1984",hash)