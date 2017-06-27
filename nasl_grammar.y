%{

#define YYERROR_VERBOSE 1
#define YYDEBUG 1
extern int yylineno;
%}



%token  FUNCTION QW OBJECT

%token LOCAL
%token GLOBAL
%token VAR
%token PUBLIC

%token SWITCH
%token CASE DEFAULT SW_AS

%token IF
%token ELSE
%token INCLUDE
%token EXPORT
%token IMPORT

%token RETURN
%token BREAK
%token CONTINUE

%token FOR
%token FOREACH
%token IN_ITER
%token WHILE
%token REPEAT
%token REP
%token UNTIL

%token IDENT
%token INT
%token STRING

%token FALSE
%token _NULL_
%token TRUE

%token OR AND ADD_ASS SUB_ASS SUBSTR_EQ SUBSTR_NEQ REGEX_EQ REGEX_NEQ DEC INC DIV_ASS MUL_ASS MOD_ASS POWER

%token CMP_EQ CMP_GE CMP_LE CMP_NEQ SL SR SRR SRR_ASS SR_ASS SL_ASS
	
%start nasl_script
%%
/**************************
		START
**************************/
nasl_script:			 
						| lines
						;
/**************************
		Lines
***************************/
lines: 					line
						| lines line
						;

line: 					 export
						| function
						| command
						| block
						| object
						;

/******************************
		Describe of lines
******************************/

export: 				EXPORT function
						;

function: 				FUNCTION identifier '(' parameters ')' block
						| FUNCTION identifier '(' ')' block
						| PUBLIC FUNCTION identifier '(' parameters ')' block
						| PUBLIC FUNCTION identifier '(' ')' block
						;
						
object: 				OBJECT identifier block
						;
/*****************************
		Describe of function
******************************/
	
parameters: 			parameter ',' parameters
						| parameter
						;

parameter: 				 '&' identifier
						| assign
						| argument
						;

/********************************
********************************/
command: 				simple
						| compound
						;
/*****************************
	   Simple commands
******************************/		 
simple: 				assign 
						| call_function ';'
						| break
						| continue
						| return
						| local
						| varib
						| global
						| inc_dec_exp
						| rep
						| import
						| include
						| empty
						;
		 
/******************************
Describe of  simple commands
******************************/

break:					BREAK ';'
						;
						
continue:				CONTINUE ';'
						;
						
import:					IMPORT '(' string ')' ';'
						;
						
include:				INCLUDE '(' string ')' ';'
						;
						
return:					RETURN expression ';'
						| RETURN '@' ';'
						| RETURN '@' identifier ';'
						| RETURN body ';'
						;
						
empty:					';'
						;

global: 				GLOBAL vars ';'
						;

local: 					LOCAL vars ';'
						;	

varib: 					VAR vars ';'
						;						

rep: 					call_function REP integer ';'
						| call_function REP identifier ';'
						;
						
call_function:		 	identifier '(' parameters ')'
						| identifier '(' ')'
						| identifier body_enum_sq '(' ')'
						| identifier body_enum_sq '(' parameters ')'
						| identifier body_enum_sq body_enum_p '(' ')'
						| identifier body_enum_sq body_enum_p '(' parameters ')'
						| identifier body_enum_p '(' ')'
						| identifier body_enum_p '(' parameters ')'
						| identifier QW identifier '(' parameters ')'
						| identifier QW identifier QW identifier '(' parameters ')'
						;
/******************************
			Operations
******************************/
assign: 			 '=' value
					| identifier '=' value
					| identifier '=' assign
					| identifier '=' ref
					| identifier body_enum_sq '=' value
					| identifier '=' list_int
					| identifier body_enum_sq '=' list_int
					| identifier body_enum_sq '=' assign
					| identifier body_enum_sq '=' ref
					| assign_math_op
					| assign_shift_op
					| '(' assign ')'
					;
					
inc_dec_exp:	 	INC identifier
					| DEC identifier
					| identifier INC
					| identifier DEC
					| INC identifier body_enum_sq
					| DEC identifier body_enum_sq
					| identifier body_enum_sq INC
					| identifier body_enum_sq DEC
					;
					
assign_math_op: 	identifier ADD_ASS value
					| identifier SUB_ASS value
					| identifier MUL_ASS value
					| identifier DIV_ASS value
					| identifier MOD_ASS value
					| identifier body_enum_sq ADD_ASS value
					| identifier body_enum_sq SUB_ASS value
					| identifier body_enum_sq MUL_ASS value
					| identifier body_enum_sq DIV_ASS value
					| identifier body_enum_sq MOD_ASS value
					;

assign_shift_op:	identifier SR_ASS value
					| identifier SRR_ASS value
					| identifier SL_ASS value
					;
	
/******************************
******************************/
value:				expression
					;
					
identifier: 		IDENT
					| IN_ITER
					| REP
					;

integer: 			INT
					| TRUE
					| FALSE
					;

string: 			STRING 
					;

ip: 				integer '.' integer '.' integer '.' integer
					;

null: 				_NULL_
					;	

ref:				'@' IDENT
					;
/******************************
		Compound commands
******************************/		 
compound: 				for_loop
						| foreach_loop
						| repeat_loop
						| while_loop
						| if_cond
						| command ELSE
						| switch
						;
		
/******************************
Describe of compound commands
******************************/
for_loop:				FOR '(' if_expr ';' if_expr ';' if_expr ')' block
						| FOR '(' if_expr ';' if_expr ';' if_expr ')' command
						;

foreach_loop:			FOREACH identifier '(' if_expr ')' block
						| FOREACH identifier '(' if_expr ')' command
						| FOREACH '(' identifier IN_ITER if_expr ')' block
						| FOREACH '(' identifier IN_ITER if_expr ')' command
						;
						
repeat_loop:			REPEAT block UNTIL if_expr
						| REPEAT command ';' UNTIL if_expr
						;
						
while_loop:				WHILE '(' if_expr ')' block
						| WHILE '(' if_expr ')' command
						;
						
if_expr:				expression
						| assign
						| if_expr AND if_expr
						| if_expr OR if_expr
						| if_expr '>' if_expr
						| if_expr '<' if_expr
						;
						
if_cond: 				IF '(' if_expr ')' block
						| IF '(' if_expr ')' command
						| IF '(' if_expr ')' block ELSE command
						| IF '(' if_expr ')' command ELSE command
						| IF '(' if_expr ')' block ELSE block
						| IF '(' if_expr ')' command ELSE block
						;
						
switch:					SWITCH '(' if_expr ')' block_sw
						| SWITCH SW_AS '(' if_expr ')' block_sw
						;
						
block_sw:				 '{' cases '}'
						;
						
case: 					CASE STRING ':' lines
						| CASE IDENT ':' lines
						| CASE INT ':' lines
						| DEFAULT ':' lines
						;
						
cases: 					cases case
						| case
						;

block: 					
						 '{' '}'
						| '{' lines '}'

body:		
						 '{' argument_list '}'
						;
						
body_sq:				 '[' ']'
						| '[' argument_list ']'
						| '[' integer ']'
						| '[' identifier ']'
						;
						
body_enum_sq:			body_enum_sq body_sq
						| body_sq
						;
						
body_p:				 	'.' identifier
						;
						
body_enum_p:			body_enum_p body_p
						| body_p
						;
						
/****************************
		Arguments and variables
*****************************/

var: 					identifier '=' value
						| identifier '=' ref
						| identifier
						;

vars: 					var ',' vars
						| var
						;

list_int: 				list_int ',' integer 
						| integer ',' integer
						;
						
argument_list:			argument_list ',' argument
						| argument 
						;
						
argument:				string ':' expression
						| integer ':' expression
						| string ':' ref
						| integer ':' ref
						| identifier ':' expression 
						| identifier ':' ref
						| expression
						| ref
						;

/****************************
*****************************/
expression: 		| '(' expression ')'
					| expression AND expression
					| '!' expression
					| expression OR expression
					| expression '+' expression
					| expression '-' expression
					| expression '=' expression
					| '-' expression 
					| expression '*' expression
					| expression POWER expression
					| expression '/' expression
					| expression '%' expression
					| expression '&' expression
					| expression '^' expression
					| expression '|' expression
					| expression SR expression
					| expression SL expression
					| expression SRR expression
					| expression SUBSTR_EQ expression
					| expression SUBSTR_NEQ expression
					| expression REGEX_NEQ expression
					| expression REGEX_EQ expression
					| expression '<' expression
					| expression '>' expression
					| expression CMP_GE expression
					| expression CMP_LE expression
					| expression CMP_EQ expression
					| expression CMP_NEQ expression
					| identifier body_enum_p
					| '~' expression
					| identifier
					| integer
					| string
					| ip
					| null
					| body
					| body_sq
					| identifier body
					| identifier body_enum_sq
					| call_function
					| inc_dec_exp 
					;
%%
#include <stdio.h>
extern char yytext[];
extern int column;
yyerror(char const *s)
{
	
	//printf("\n%d\n", yylineno);
	fflush(stdout);
	printf("\n%*s\n%*s\n", column+8, "^", column+8, s);
}

lex()
{
	printf("\n%s\n", stdin);
}
int main()
{
	
	return(yyparse());
}
