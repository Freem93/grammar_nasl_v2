#
# KillerApp check
#


for( ; ; )
{
	display(i, "\n");
}

j = 1;

while(true)
{
	display(j, "\n");
	j += 1;
}

#if tests

if (-1);
if (0);
if (1);
if (q = 1);
if (foo());
if (FALSE);
if (TRUE);
if (NULL);
if ('');
if ('foo');
if ("");
if ("foo");
if (1) {}
if (1) if (1) foo();
if (1) if (1) {foo();}
if (1) if (1) foo(); else bar();
if (foo) {};

#tests array

foo = {};
foo = {1:02, 3:4, 5:0x6};
foo = {'a':"b", "c":'d'};
foo = {'a':1, 2:"b"};
#foo = {'a':1, 2:"b",}; #must be fail?
#foo = {'a':1, 2:"b",,}; #must be fail
#return {,}; #must be fail
return {a:@foo, b:"h", c:3};

#assigment tests

q = 0;
q = '';
q = 'foo';
q = "";
q = "foo";
q = foo();
q = @foo;
b = a = 0;
b = 1 + a = 0;
c = 1 + b = 1 + a = 0;
q = 0 + 0;
q = 0 - 0;
q = 0 * 0;
q = 0 / 0;
q = 0 % 0;
if (q = foo());
while (q = foo());
q = [];
#todo# q = [[[]], [[]], [[]]];
q = [1];
#todo# q = [1, 'b', foo()];
foo(arg:[1]);
q = [] + [];
q = [] + [];
#todo# q = {'a':{'b':{}}, 'c':{'d':{}}, 'e':{'f':{}}};
q = {"a":1};
q = {1:1, 2:'b', 3:foo()};
foo(arg:{1:1});
q = {} + {};

#test blank
;
;;
;;;

#test block

{
	a = 1;
	break;
	fn();
	;
}


{}

{;}
{
#
}


#test call


#break(); #must be fail
#continue(); #must be fail
#else(); #must be fail
#export(); #must be fail
#for(); #must be fail
#foreach(); #must be fail
#function(); #must be fail
#global_var(); #must be fail
#if(); #must be fail
#import(); #must be fail
#include(); #must be fail
#local_var(); #must be fail
#local_var(); #must be fail
#return(); #must be fail
#until(); #must be fail
#while(); #must be fail
#todo# FALSE(); #must be fail
#todo# NULL(); #must be fail
#todo# TRUE(); #must be fail

in();
x();
break_();
continue_();
else_();
export_();
export_();
foreach_();
function_();
global_var_();
if_();
import_();
include_();
local_var_();
repeat_();
return_();
until_();
while_();
FALSE_();
NULL_();
TRUE_();

#todo# foo[a][1]['b'][c+d].e.f.g(); #test_no_args
#todo# foo[a][1]['b'][c+d].e.f.g(1, '2', three); #test_anonymous_args
#todo# foo[a][1]['b'][c+d].e.f.g(a:1, b:'2', c:three) #test_named_args
#todo# foo[a][1]['b'][c+d].e.f.g(a:1, '2', c:three, bar()); #test_mixed_args


#Constant tests
z = FALSE;
z = NULL;
z = TRUE;


#Expression tests
q = (-a);
q = (a);
q = (~a);
q = (a + b);
q = (a + (b + c));
q = ((a + b) + (b + d));
q = (a + b) == c;
q = (a + b) == (c + d);
q = ((a + b) == (c + d));
q = (a + b) >> c;
q = (a + b) >> (c + d);
q = ((a + b) >> (c + d));
q = (((1)));
q = (((a = b)));

q = 0 | 1;
q = 0 & 1;

#todo# q = a.b; #test period
#todo# q = a._;
#q = a.1 #must be fail
q = a + b / c + d;

#foreach tests

foreach foo (bar);
foreach (foo in bar);
foreach foo (bar);

#test functions

#function break() {} #must be fail
#function continue() {} #must be fail
#function else() {} #must be fail
#function export() {} #must be fail
#function for() {} #must be fail
#function foreach() {} #must be fail
#function function() {} #must be fail
#function global_var() {} #must be fail
#function global_var() {} #must be fail
#function import() {} #must be fail
#function include() {} #must be fail
#function repeat() {} #must be fail
#function return() {} #must be fail
#function until() {} #must be fail
#function while() {} #must be fail
#todo# function FALSE() {} #must be fail
#todo# function NULL() {} #must be fail
#todo# function TRUE() {} #must be fail
#function in() {} #must be fail
#todo# function x() {} #must be fail


function break_() {}
function continue_() {}
function else_() {}
function export_() {}
function for_() {}
function foreach_() {}
function function_() {}
function global_var_() {}
function if_() {}
function import_() {}
function include_() {}
function local_var_() {}
function repeat_() {}
function return_() {}
function until_() {}
function while_() {}

function FALSE_() {}
function NULL_() {}
function TRUE_() {}

function foo() {} #test no args
function foo(a, b, c) {} #test named args
function foo(&a, &b, &c) {} #test ref args
function foo(a, &b, c) {} #test mixed args


#test global

#global_var; #must be fail
global_var a, b, c;
global_var a = 1;
global_var a = 1, b = 2, c = 3;
global_var a = @a, b = @b, c = @c; #test_assign_reference
global_var a, b = 2, c = @c;


#test include

#include (); #must be fail
include ('');
include ('q.inc');
include ("");
include ("q.inc");


#test incr decr

#q()++; #must be fail

q++;
q[1]++;
#todo# q[1][2]++;
#todo# q[1][3]++;

++q;
++q[1];
#todo# ++q[1][2];
#todo# ++q[1][3];

q["a"]++;
#todo# q["a"]["b"]++;
#todo# q["a"]["b"]["c"]++;

++q["a"];
#todo# ++q["a"]["b"];
#todo# ++q["a"]["b"]["c"];


#test ip

q = 1.1.1.1;


#test list

foo = [];


#test locals

#local_var; #must be fail

local_var a, b, c;
local_var a = 1, b = 2, c = 3;
local_var a = @a, b = @b, c = @c;
local_var a, b = 2, c = @c;


#test repetition

#todo# exit() x 10;
#todo# exit(2, 3) x 10;


#return tests

#return() #must be fail
#return(); #nust be fail
#return[] #must be fail
#return{} #must be fail

return;
return[];
return [];
return{};
return {};

return(a + b)==c;
return a;


#stirngs test

z = '';
z = "";
z = '\\'';
z = '\\\\';
z = "\\";
z = "\\\\";
z = 'foo\nbar';
z = "foo\nbar";


#while tests

while (foo) {}


#test whitespaces

#
 #
##
# foo\n# bar


#if (); #must be fail
#todo# if (1) #must be fail

#if(){} #must be fail


if(1){}
if(1){}
if (1) {}
if (1) {;}
if (1) {;;}
if (1)
{
	
}
