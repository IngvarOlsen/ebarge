CREATE TABLE `Container` (
    `ID` int PRIMARY KEY AUTOINCREMENT ,
    `loadingDate` datetime  NOT NULL
);

CREATE TABLE `Readings` (
    `ID` int PRIMARY KEY AUTOINCREMENT ,
    `temp` decimal  NOT NULL ,
    `humid` decimal  NOT NULL ,
    `containerID` int  NOT NULL
);

