#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <cassert>
#include "ec_ops.h"

#include <time.h>
#include <gmp.h>

using namespace std;

Zp Zp::inverse() const {
	// Implement the Extended Euclidean Algorithm to return the inverse mod PRIME

    // The below does NOT use the Extended Euclidean Algorithm.
    // But is WAS easy to implement.  We will swap out later and verify against this performance
    string s = value.convert_to_string();
    string p = PRIME.convert_to_string();
    mpz_t mpz_value, mpz_prime;

    mpz_init_set_str(mpz_value,s.c_str(),0);
    mpz_init_set_str(mpz_prime,p.c_str(),0);

    mpz_invert(mpz_value, mpz_value, mpz_prime);    // now mpz_value holds the inverse

    char a[256];
    mpz_get_str (a, 10, mpz_value);
    uberzahl retval(a);

    mpz_clear(mpz_value);
    mpz_clear(mpz_prime);
	return retval;
}


ECpoint ECpoint::operator + (const ECpoint &a) const {
	// Implement  elliptic curve addition
    Zp lambda, denom;

    // First some special cases
	if(    a.infinityPoint) return ECpoint(this->x,this->y);
	if(this->infinityPoint) return ECpoint(  a.x,    a.y);

    Zp x_P(    a.x);
    Zp y_P(    a.y);
    Zp x_Q(this->x);
    Zp y_Q(this->y);

    // Check for special case: point at infinity
	if(x_P == x_Q && y_P == (-y_Q)) return ECpoint(1);

    if( x_P == x_Q && y_P == y_Q) {   // special case for lambda
        denom  = Zp(2)*y_P;
        lambda = (Zp(3)*x_P*x_P+A)*denom.inverse();
    } else {
        denom  =  x_Q - x_P;
        lambda = (y_Q - y_P)*denom.inverse();
    }

    Zp x_R = lambda*lambda-x_P-x_Q;
    Zp y_R = lambda*(x_P-x_R)-y_P;

	return ECpoint(x_R,y_R);
}


ECpoint ECpoint::repeatSum(ECpoint p, uberzahl v) const {
	//Find the sum of p+p+...+p (vtimes)
	ECpoint retPoint(1);
	uberzahl mask("1");
	uberzahl zmask("0");

	while(v != zmask) {
        if((v & mask) == mask) retPoint = retPoint + p;
        p = p+p;
        v = v>>1;
	}

	return retPoint;
}

Zp ECsystem::power(Zp val, uberzahl pow) {
	//Find the product of val*val*...*val (pow times)

    uberzahl uz_value(val.getValue());
    string s       = uz_value.convert_to_string();
    string s_power = pow.convert_to_string();
    string p       = PRIME.convert_to_string();

    mpz_t mpz_value, mpz_power, mpz_prime;
    mpz_init_set_str(mpz_value,      s.c_str(),0);
    mpz_init_set_str(mpz_power,s_power.c_str(),0);
    mpz_init_set_str(mpz_prime,      p.c_str(),0);

    mpz_powm(mpz_value, mpz_value, mpz_power, mpz_prime);

    char a[256];
    mpz_get_str (a, 10, mpz_value);
    uberzahl retval(a);

    Zp Zp_retval(retval);

    mpz_clear(mpz_value);
    mpz_clear(mpz_power);
    mpz_clear(mpz_prime);

	return Zp_retval;
}


uberzahl ECsystem::pointCompress(ECpoint e) {
	//It is the gamma function explained in the assignment.
	//Note: Here return type is mpz_class because the function may
	//map to a value greater than the defined PRIME number (i.e, range of Zp)
	//This function is fully defined.
	uberzahl compressedPoint = e.x.getValue();
	compressedPoint = compressedPoint<<1;

	if(e.infinityPoint) {
		cout<<"Point cannot be compressed as its INF-POINT"<<flush;
		abort();
		}
	else {
		if (e.y.getValue()%2 == 1)
			compressedPoint = compressedPoint + 1;
		}
		//cout<<"For point  "<<e<<"  Compressed point is <<"<<compressedPoint<<"\n";
		return compressedPoint;

}

ECpoint ECsystem::pointDecompress(uberzahl compressedPoint){
	//Implement the delta function for decompressing the compressed point

	assert(0);
	return ECpoint(true);
}


pair<pair<Zp,Zp>,uberzahl> ECsystem::encrypt(ECpoint publicKey, uberzahl privateKey,Zp plaintext0,Zp plaintext1){
	// You must implement elliptic curve encryption
	//  Do not generate a random key. Use the private key that is passed from the main function

	assert(0);
	return make_pair(make_pair(0,0),0);
}


pair<Zp,Zp> ECsystem::decrypt(pair<pair<Zp,Zp>, uberzahl> ciphertext){
	// Implement EC Decryption

	assert(0);
	return make_pair(0,0);
}


/*
 * main: Compute a pair of public key and private key
 *       Generate plaintext (m1, m2)
 *       Encrypt plaintext using elliptic curve encryption
 *       Decrypt ciphertext using elliptic curve decryption
 *       Should get the original plaintext
 *       Don't change anything in main.  We will use this to
 *       evaluate the correctness of your program.
 */


int main(void){
	srand(time(0));
	ECsystem ec;
	unsigned long incrementVal;
	pair <ECpoint, uberzahl> keys = ec.generateKeys();


	Zp plaintext0(MESSAGE0);
	Zp plaintext1(MESSAGE1);

    ECpoint a(GX,GY);
    ECpoint b = a;
    for(int i = 1; i <= 50; i++) {
        cout << i << "G = " << endl
        << a.repeatSum(b,uberzahl(i))  << endl
        << a << endl;
        a = b+a;

    }
    cout << endl;

	ECpoint publicKey = keys.first;
	cout << "Public key is: " << publicKey << endl;

//	cout << "Enter offset value for sender's private key" << endl;
//	cin  >> incrementVal;
//	uberzahl privateKey = XB + incrementVal;

//	pair<pair<Zp,Zp>, uberzahl> ciphertext
//        = ec.encrypt(publicKey, privateKey, plaintext0,plaintext1);
//	cout << "Encrypted ciphertext is: ("
//         << ciphertext.first.first << ", "
//         << ciphertext.first.second << ", "
//         << ciphertext.second <<")\n";
//	pair<Zp,Zp> plaintext_out = ec.decrypt(ciphertext);

//	cout << "Original plaintext is: (" << plaintext0 << ", " << plaintext1 << ")\n";
//	cout << "Decrypted plaintext: (" << plaintext_out.first << ", " << plaintext_out.second << ")\n";


//	if(plaintext0 == plaintext_out.first && plaintext1 == plaintext_out.second)
//		cout << "Correct!" << endl;
//	else
//		cout << "Plaintext different from original plaintext." << endl;
//    cout << keys << endl;
	return 1;

}
