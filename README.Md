# Hacky Tunnels for Freenet

Recently, a paper evaluating the security of Freenet pointed out the fact that immediate neighbors can see specific blocks being routed. If you're using opennet or it just turns out that your darknet friend is a rat bastard, they can watch for blocks being routed through your node. If they can match enough of those blocks to a manifest in a certain time period, they can say with some probability that you may be requesting the content associated with a specific manifest. Then I guess law enforcement locks people up or something. This is what we call bad. 

How can we have out of band encrypted communication using standard Freenet primitives?

Ladies, Gentlemen and Others:
A simple method

## Here's how it works. 

1) Everybody has standard RSA keys.

2) Public keys are shared with other users. People decide if they trust them or not. If so, proceed.

3) A KSK is established using a deterministic codeword - a combination of the hash of both keys 

4) The node who wants to communicate sends a signed & encrypted message with a randomly generated KSK inside of it. 

5) The other node, who is willingly polling the codeword KSK decrypts the message and begins listening on the new channel after checking signature.

6) The person with the material encrypts it separately with a long AES key. They insert the content and share the signed & encrypted AES key and the URI of the corresponding content to the randomly generated KSK. 

7) The recipient who is polling the random KSK sees the content, verifies the signature and begins fetching the URI. The application then decrypts the content and saves it to disk. 

This should allow for private channels that are extremely difficult to find over freenet whereby content can be sent to one recipient or a small group of recipients. All transmitted blocks cannot be matched to incriminating content unless the attacker can both determine the manifest of the material being requested and break a long AES key. Group communication is still achievable either by sharing the same URI and AES key combo or by generating a new URI and AES combo for every recipient - sharing the same key+uri combo with more people represents a larger risk, as the main threat is now the key being leaked. Generating and inserting content encrypted with a new key is safer but obviously slower. On opennet, speed should be less of an issue. 

# BUT CAN'T FREEMAIL DO THIS?!?!

Yes. But Freemail uses WoT, which is unreliable, bloated, slow and generally useless. Also, this allows two people to simply swap keys over any channel(email, sneakernet, etc) and establish a covert channel. Out of band communication is valuable. 

This is a python PoC. If people like it I might build it out more to do full file sharing and messaging for groups.

If you like my work, send me some Monero, friend:
84EoPCkKCc5fi3jdNRRfbzYWSdZYGN25XHfDoSZJw3sgRarp2nYrA5EHbcYWdmfYizS8QaumVNfUrT7mEs724XfjGQDvwbC

If you don't have Monero but do have some other currency, consider sending it my address via shapeshift.io

## Try it out

To run the PoC, you need Python 2.7, PyCrypto and pyFreenet. 

I used the version of pyFreenet cloned from: https://github.com/freenet/pyFreenet

Simply cloning this repository and running python setup.py install should be enough.

Then run cryptoshare.py and the demo will run.
