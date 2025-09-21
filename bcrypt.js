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


hashPassword("admin")
const hash = "$2b$10$Ne3lZ05ptMmfG1N5/tGit.8ndLPlX2f69.S3RCoiwfJM2zlOu40e.";
//$2b$20$c3N9dBVXvf8.LSk6172bvufku/aybDOUQm7Tps01Y/PDEUy7L9w9G
//$2b$15$zdDQpUqy4kg/HcE4s5Jrkuk2N2gG9HXls9az0tzmN7AWe.jYaVEKe
//$2b$04$4j2esITs7r3Xs2FnDC028un6lvRUpcrOzmZlChz34Krq0q7MUe12.
//$2b$04$XW/uDKsMRx6wzxLnITZmdOOkRvgVw0EfwcD.G0LNXN7/9K87rPTOK
checkPassword("admin",hash)