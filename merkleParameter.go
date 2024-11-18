package main

var write = 1

var leafIndex = 1 //证明叶子结点的索引

// var datasize = 262144000
var datasize = dag_size * 2

var dag_size = 128000 //每个dag节点的大小，最大为256KB

var leafnum = datasize / dag_size //叶子结点个数

var chalnum = datasize / dag_size //挑战块的个数
