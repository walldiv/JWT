DROP TABLE IF EXISTS users, passwordreset;

create table users (
    userid SERIAL primary key,
    firstname varchar(30),
    lastname varchar(30),
    dateofbirth timestamp,
    username varchar(30),
    email varchar(30),
    password varchar(60),
    role varchar(30),
    authorities varchar(20),
    joindate timestamp,
    lastlogindate timestamp,
    islockedout boolean,
    isaccountverified boolean
);

create table passwordreset (
    token varchar(60) primary key,
    email varchar(30),
    expirationtime timestamp
);

