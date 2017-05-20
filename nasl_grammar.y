%{

#define YYERROR_VERBOSE 1
#define YYDEBUG 1
extern int yylineno;
%}

%token COMMENT

%token FUNCTION

%token LOCAL
%token GLOBAL

%token ELSE
%token IF

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

line: 					COMMENT
						| export
						| function
						| command
						;

/******************************
		Describe of lines
******************************/

export: 				EXPORT function
						;

function: 				FUNCTION identifier '(' parameters ')' block
						| FUNCTION identifier '(' ')' block
						;
/*****************************
		Describe of function
******************************/
	
parameters: 			parameter ',' parameters
						| parameter
						;

parameter: 				identifier
						| '&' identifier
						| assign
						| string
						| integer
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
						| RETURN body ';'
						;
						
empty:					';'
						;

global: 				GLOBAL vars ';'
						;

local: 					LOCAL vars ';'
						;						

rep: 					call_function REP expression ';'
						;
						
call_function:		 	identifier '(' parameters ')'
						| identifier '(' ')'
						;
/******************************
			Operations
******************************/
assign: 			 '=' value
					| identifier '=' value
					| identifier '=' body
					| identifier '=' call_function
					| identifier '=' assign
					| identifier '=' ref
					| assign_math_op
					| assign_shift_op
					;
					
inc_dec_exp:	 	INC identifier
					| DEC identifier
					| identifier INC
					| identifier DEC
					;
					
assign_math_op: 	identifier ADD_ASS value
					| identifier SUB_ASS value
					| identifier MUL_ASS value
					| identifier DIV_ASS value
					| identifier MOD_ASS value
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
						;
		
/******************************
Describe of compound commands
******************************/
for_loop:				FOR '(' expression ';' expression ';' expression ')' block
						| FOR '(' expression ';' expression ';' expression ')' command
						;

foreach_loop:			FOREACH identifier '(' expression ')' block
						| FOREACH identifier '(' expression ')' command
						| FOREACH '(' identifier IN_ITER expression ')' block
						| FOREACH '(' identifier IN_ITER expression ')' command
						;
						
repeat_loop:			REPEAT block UNTIL expression ';'
						| REPEAT command UNTIL expression ';'
						;
						
while_loop:				WHILE '(' if_expr ')' block
						| WHILE '(' if_expr ')' command
						;
						
if_expr:				expression
						| assign
						| call_function
						;
						
if_cond: 				IF '(' if_expr ')' block
						| IF '(' if_expr ')' command
						| IF '(' if_expr ')' block ELSE command
						| IF '(' if_expr ')' block ELSE block
						| IF '(' if_expr ')' command ELSE block
						| IF '(' if_expr ')' command ELSE command
						;

block: 					
						| '{' '}'
						| '{' lines '}'

body:		
						 '{' argument_list '}'
		 				| '[' ']'
						| '[' argument_list ']'
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
					| identifier
					| integer
					| string
					| ip
					| null
					;
%%
#include <stdio.h>
extern char yytext[];
extern int column;
yyerror(char const *s)
{
	
	//printf("\n%d\n", yylineno);
	fflush(stdout);
	printf("\n%*s\n%*s\n", column+7, "^", column+7, s);
}

lex()
{
	printf("\n%s\n", stdin);
}
int main()
{
	
	return(yyparse());
}
