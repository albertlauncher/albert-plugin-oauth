cmake_minimum_required(VERSION 3.16)
project(oauth VERSION 1.0)

find_package(Albert REQUIRED)

albert_plugin(
    INCLUDE
        INTERFACE include
        PRIVATE include/albert/plugin
    QT
        Widgets Network NetworkAuth
)
