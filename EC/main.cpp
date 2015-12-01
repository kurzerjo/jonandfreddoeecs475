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

    // We want to find the inverse of a, so
    // x(a) + y*(b) = 1
    // will result in x = inverse of a
    uberzahl a(this->value);
    uberzahl x(0),y(1),u(1),v(0),b(PRIME);  // vars with initial values
    uberzahl q,r,m,n;                       // temp variables
    while(a > 0) {
        q = b/a;    // calculate quotient
        r = b%a;    // calculate remainder
        m = x-u*q;  //
        n = y-v*q;  //
        b = a;      //
        a = r;      //
        x = u;      //
        y = v;      //
        u = m;      //
        v = n;      //
    }
    return x;
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
        denom  = y_P + y_P;
        lambda = ( (x_P + x_P + x_P) * x_P + A) * denom.inverse();
    } else {
        denom  =  x_Q - x_P;
        lambda = (y_Q - y_P)*denom.inverse();
    }

    Zp x_R = lambda*lambda-x_P-x_Q;
    Zp y_R = lambda*(x_P-x_R)-y_P;

	return ECpoint(x_R,y_R);
}


ECpoint ECpoint::repeatSum(ECpoint p, uberzahl v) const {
	//Find the sum of p+p+...+p (v times)

	assert(v >= 0);
    ECpoint retPoint(1);    // initialize retPoint to the point at infinity

	while(v > 0) {
        if(v.bit(0)) retPoint = retPoint + p;
        v = v >> 1;
        p = p + p;
	}

	return retPoint;
}

Zp ECsystem::power(Zp val, uberzahl pow) {
	//Find the product of val*val*...*val (pow times)

    assert(pow >= 0);

    Zp result(1);       // base case
	uberzahl mask("1");
	uberzahl zmask("0");
	while(pow != zmask) {
        if((pow & mask) == mask) result = result * val;
        pow = pow>>1;
        val = val*val;
	}
	return result;
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
		cout << "For point  " << e
		     << ", Compressed point is " << compressedPoint << endl;
		return compressedPoint;

}

ECpoint ECsystem::pointDecompress(uberzahl compressedPoint){
	//Implement the delta function for decompressing the compressed point

    uberzahl pairTest(compressedPoint & 1);
    Zp x(compressedPoint >> 1);
    Zp y(compressedPoint >> 1);

    y = y*y*y + Zp(A)*y + Zp(B);
    y = power(y,(PRIME+1)>>2);

    if(pairTest == 0) y = Zp(PRIME) - y;

//    cout << "For compressed point " << compressedPoint
//         << ", Point is " << ECpoint(x,y) << endl;
	return ECpoint(x,y);
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

//    for(int i = 1; i <= 5; i++) {
//        ECpoint a(5,2);
//        a = a.repeatSum(a,uberzahl(i));
//        ec.pointDecompress(ec.pointCompress(a));
//    }

//    ECpoint b = a;
//    for(int i = 1; i <= 50; i++) {
//        cout << i << "G = " << endl
//        << a.repeatSum(b,uberzahl(i))  << endl
//        << a << endl;
//        a = b+a;
//
//    }
//    cout << endl;
    for(int i = 1; i < 11; i++) {
            for(int j = 1; j < 11; j++) {
                Zp a(i);
                Zp b(a.inverse());
                Zp c(a*b);
                cout << a << "*" << b << "%" << PRIME
                     << "=" << c << endl;
                assert(c == 1);
            }
    }
    cout << endl;

//	ECpoint publicKey = keys.first;
//	cout << "Public key is: " << publicKey << endl;


//	cout << "Enter offset value for sender's private key" << endl;
//	cin  >> incrementVal;
//	uberzahl privateKey = XB + incrementVal;
//
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
