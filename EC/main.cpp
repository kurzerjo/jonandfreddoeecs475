#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <cassert>

#include <time.h>  // I had to add this to make the rand seed work

#include "ec_ops.h"
using namespace std;

Zp Zp::inverse() const {
	// Implement the Extended Euclidean Algorithm to return the inverse mod PRIME

    uberzahl a(this->value);
    uberzahl x(0),y(1),u(1),v(0),b(PRIME);  // vars with initial values
    uberzahl q,r,m,n;                       // temp variables
    while(a > 0) {
        q = b/a;
        r = b%a;
        m = x-u*q;
        n = y-v*q;

        b = a;
        a = r;

        x = u;
        y = v;

        u = m;
        v = n;
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
	//Find the sum of p+p+...+p (vtimes)

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

    return compressedPoint;
}

ECpoint ECsystem::pointDecompress(uberzahl compressedPoint){
	//Implement the delta function for decompressing the compressed point

    uberzahl pairTest(compressedPoint & 1);
    Zp x(compressedPoint>>1);
    Zp y(compressedPoint >> 1);

    y = y*y*y + Zp(A)*y + Zp(B);
    y = power(y,(PRIME+1)>>2);

    if(pairTest == 0) y = Zp(PRIME) - y;

	return ECpoint(x,y);
}


pair<pair<Zp,Zp>,uberzahl> ECsystem::encrypt(ECpoint publicKey, uberzahl privateKey,Zp plaintext0,Zp plaintext1){
	// You must implement elliptic curve encryption
	//  Do not generate a random key. Use the private key that is passed from the main function

	ECpoint Q, R;
	Zp C0, C1;
	uberzahl C2;

	Q = privateKey * G;
	R = this->G.repeatSum(publicKey, privateKey);
    cout << Q << endl;
	C0 = plaintext0*R.x;
	C1 = plaintext1*R.y;
	C2 = pointCompress(Q);

	return make_pair(make_pair(C0,C1),C2);
}

pair<Zp,Zp> ECsystem::decrypt(pair<pair<Zp,Zp>, uberzahl> ciphertext){
	// Implement EC Decryption

	Zp C0(ciphertext.first.first);
	Zp C1(ciphertext.first.second);
	uberzahl C2(ciphertext.second);

	ECpoint R(this->G.repeatSum(pointDecompress(C2),privateKey));
	Zp M0(C0*R.x.inverse());
	Zp M1(C1*R.y.inverse());


	return make_pair(M0,M1);
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
	ECpoint publicKey = keys.first;
	cout<<"Public key is: "<<publicKey<<"\n";

	cout<<"Enter offset value for sender's private key"<<endl;
	cin>>incrementVal;
	uberzahl privateKey = XB + incrementVal;

	pair<pair<Zp,Zp>, uberzahl> ciphertext = ec.encrypt(publicKey, privateKey, plaintext0,plaintext1);
	cout<<"Encrypted ciphertext is: ("<<ciphertext.first.first<<", "<<ciphertext.first.second<<", "<<ciphertext.second<<")\n";
	pair<Zp,Zp> plaintext_out = ec.decrypt(ciphertext);

	cout << "Original plaintext is: (" << plaintext0 << ", " << plaintext1 << ")\n";
	cout << "Decrypted plaintext: (" << plaintext_out.first << ", " << plaintext_out.second << ")\n";


	if(plaintext0 == plaintext_out.first && plaintext1 == plaintext_out.second)
		cout << "Correct!" << endl;
	else
		cout << "Plaintext different from original plaintext." << endl;

	return 1;

}
