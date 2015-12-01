// Project partner note: Jonathan Kurzer (kurzerjo) and Fred Buhler (fbuhler)

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <cassert>

#include <time.h>  // I had to add this to make the rand seed work

#include "ec_ops.h"
using namespace std;

void gcd(uberzahl a, uberzahl b, uberzahl *g, uberzahl *x, uberzahl *y) {
    // This is the inverse helper function

    // returns (g,x,y) such that a(x) +  b(y) = g = gcd(a,b)

    // Base case
    if(a == 0) { *g = b; *x = 0; *y = 1; return;}

    else {
        uberzahl g_, y_, x_; // some temp vars to hold our data
        gcd( b%a, a, &g_, &y_, &x_);    // Call the recursive function

        // Update values to pass up by reference
        *g = g_;
        *x = x_ - (b/a) * y_;
        *y = y_;
    }
    return;
}
Zp Zp::inverse() const {
	// Implement the Extended Euclidean Algorithm to return the inverse mod PRIME

    uberzahl a(this->value);
    uberzahl m(PRIME);      // vars with initial values

    uberzahl g,x,y;         // temp variables
    gcd(a, m, &g, &x, &y);  // Helper function

    return Zp(x);           // Cast and return inverse (mod PRIME)
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

    Zp x_R = lambda*lambda-x_P-x_Q; // Equations directly from project spec
    Zp y_R = lambda*(x_P-x_R)-y_P;

	return ECpoint(x_R,y_R);
}


ECpoint ECpoint::repeatSum(ECpoint p, uberzahl v) const {
	//Find the sum of p+p+...+p (vtimes)
	ECpoint retPoint(1);    // initialize retPoint to the point at infinity
	uberzahl mask("1");
	uberzahl zmask("0");

    // Calculate the "multiplication" using repeated "squaring"
	while(v != zmask) {
        if((v & mask) == mask) retPoint = retPoint + p;
        v = v >> 1;
        p = p+p;
	}

	return retPoint;
}

Zp ECsystem::power(Zp val, uberzahl pow) {
	//Find the product of val*val*...*val (pow times)

    Zp result(1);       // base case
	uberzahl mask("1");
	uberzahl zmask("0");

    // Calculate the power using repeated squaring
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

    uberzahl pairTest(compressedPoint.bit(0));
    Zp x(compressedPoint >> 1);
    Zp y(x);

    // Equations directly from project spec
    y = y*y*y + Zp(A)*y + Zp(B);
    y = power(y,(PRIME+1)/4);

    // Ensure LSB of y matches LSB of compressed point
    if(pairTest != y.getValue().bit(0)) y = Zp(PRIME) - y;

	return ECpoint(x,y);
}


pair<pair<Zp,Zp>,uberzahl> ECsystem::encrypt(ECpoint publicKey, uberzahl privateKey,Zp plaintext0,Zp plaintext1){
	// You must implement elliptic curve encryption
	//  Do not generate a random key. Use the private key that is passed from the main function

	ECpoint Q, R;
	Zp C0, C1;
	uberzahl C2;

    // Equations directly from project spec
	Q = privateKey * G;
	R = privateKey * publicKey;
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

    // Equations directly from project spec
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
