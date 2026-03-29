![](https://hackmd.io/_uploads/HyJTRZ43n.png)

Decentralized Identification and Authorization Protocol

## Introduction

DauthZ - is a general framework for identification and  authorization mechanism for any online or offline digital interaction. It is based on the simple prove of ownership of particular identifier.

DAuthZ is based on KERI which is dencetralized key management system allowing to establish control over stable digital identifier (AID) which is bound cryptographically via Key Event Log (KEL) to pair of keys (Asymetric Encryption)

DAuthZ provide coherant approach for user onboardin, authentication, identification and authorization. Taking of the developer and service provider shoulders to implement onboarding and secure authentication mechanism.

## Identification vs Authenthication

Starting with defintion of identity as:

> What makes it true that a person at one time is the same thing as a person at another time

Gives us context how we envision identity. It is not about credential, keys or passwords. It is about continuity of consciousness, personal persistence or self-continuity. You are not your keys, your password or email address, you are you.

Putting it simply in the scope of digital interaction I want to know that the person who created an account is exactly the same person when it tries to access some resources, not just a person who happen to have login and password or same credential.

`Identification` is a process which allows to establish true identity of a person while he performing certian digital operation. Identification can be very simple e.g. just checking if the user poses specific key or by complex anomaly detection, multi-layer verification, measurment of environement signals or verifing biometrics.

Example of identification mechanism:
* Data Attributes
* Observation
* Credentials
* Behaviours
* Compare present artifacts to previously captured
* Infinit amount of signal sources
* Advanced correlations and data analytics
* Biometrics

On other side `Authentication` is a process to prove that who ever accessing given resource is a legitimate account holder. Which not necessary indicates who this person realy is.

In digital space there is not many use cases where we could relay on authentication, since services are not interested in legitimate account holder but true identity of that person.
Means if someone will stole my password he would be able eaisly pass authentication on the services where he would not pass identification.

Putting that way definitions of identification and authentication we could conclude that authentication is pointless in techncial sens without any form of identification.

## How it works

DAuthZ assumes following roles:

**Entity** - entity can refer to an individual, a company, a government agency, or any other legally recognized subject with rights and responsibilities.
**Service** - refers to a technology-enabled offering that delivers value, utility, or experiences to users through digital platforms.
**SAS** - entityt digital-self aka TDA


```plantuml
entity SAS as sas
actor Entity as e
participant Service as s
collections Witness as w
== Registration ==
e -> s: Initiate a registration ceremony
s -> e: Provides challenge with Service AID and MsgBox OOBI
e -> sas: Pass challenge
sas -> w: Request KEL of service provider
sas -> sas: verifies service AID and add to contact list
e -> sas: Use existing or generate new AID
note left
User can choose existing AID,
derive new from existing
or create new
end note
sas -> e: Prompts client for identification
e -> sas: Approves
sas -> s: Deliver sign AID with challenge
s -> w: Request for KEL of provided AID
w -> s: Provides KEL
s -> s: Verifies challenge
s -> s: Create account for given AID

== Login ==

e -> s: Initiate identification ceremony
s -> e: provides identification challenge
e -> sas: pass challenge
sas -> w: Request Service AID KEL
sas -> sas: verify
sas -> e: Prompts client for identification
e -> sas: Approves
sas -> s: Signed challenge
s -> w: Request KEL
w -> s: Provides KEL
s -> s: Verifies challenge
s -> e: Grant access to the service

== Rotation ==

e -> sas: Request rotation of AID
sas -> e: Prompts client for identification
e -> sas: Approves
sas -> w: propagate new key

```


## Use cases

- onboading user to digital service
- login mechanism
- signing documents
- attestation
- witnessing

## Multi factor authentication

Multi factor authentication was introduced to protect entities from variouse types of security risks:

- weak authentication like password
- mitigate password vulnerabilitites (leaks, beaches, brute-force attacts)
- protect against phishing

Introducing DAuthZ we are eliminating those risks, there is no passwords to protect, there is no risk of phishing as the key nevers leaves Secure Element/TPM

DAuthZ increase dramatically user experience with unify flow for identification and authorization across many services and platforms, without need to compromise it's security (e.g. compering with passkey which gives away control to the platforms).

## Type of interaction

DAuthZ can be used in many different environments, online, offline, using ip based protocols or others (BT, NFC). To facilitate many different ways of data exchange DAuthZ defines general payload which simplify the way how parties interact.

```json

{
  "i": {"eid":"BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-\",\"scheme\":\"http\",\"url\":\"http://messagebox.sandbox.argo.colossi.network/\"}{\"cid\":\"EGBYsOImpwu7KVN_bBVJVnDpsfwu2QwLcV1xPkrwfskm\",\"role\":\"messagebox\",\"eid\":\"BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-\"}",
  "o": "{\"eid\":\"BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-\",\"scheme\":\"http\",\"url\":\"http://messagebox.sandbox.argo.colossi.network/\"}{\"cid\":\"BAiune9aMn_mZa0Tzegs6KjA84QpMutRr4qgIPyORZcn\",\"role\":\"messagebox\",\"eid\":\"BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-\"}",
  "s": "EF5ERATRBBN_ewEo9buQbznirhBmvrSSC0O2GIR4Gbfs"
}

```


## Implementation


### Web


