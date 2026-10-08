package com.tenix.demod;

final class Project {
    long id, created, origSize, modSize;
    String name, origUri, modUri, origName, modName, msg;
    int status, score; // status: 0 new, 1 running, 2 done, 3 failed
}
