export default class {
	static generate(message, privatekey) @ "xs_jwt_generate";
    static verify(token, publickey) @ "xs_jwt_verify";
}