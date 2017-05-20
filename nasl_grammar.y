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
%token INT_DEC
%token INT_OCT
%token INT_HEX
%token STRING

%token FALSE
%token UNDEF
%token TRUE
	
%start nasl_script
%%
/**************************
		START
**************************/
nasl_script:			 line nasl_script
						|
						;
/**************************
		Lines
***************************/
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
identifier: 			IDENT
						;
	
parameters: 			parameter ',' parameters
						| parameter
						;

parameter: 				identifier
						| '&' identifier
						| assign
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
						| call_function
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
/******************************
			Operations
******************************/
assign: 			identifier "=" value
					| assign_math_op
					| assign_shift_op
					| assign_condition_op
					;
					
inc_dec_exp:	 	"++" identifier
					| "--" identifier
					| identifier "++"
					| identifier "--"
					;
					
assign_math_op: 	identifier "+=" value
					| identifier "-=" value
					| identifier "*=" value
					| identifier "/=" value
					| identifier "%=" value
					;

assign_shift_op:	identifier ">>=" value
					| identifier ">>>=" value
					| identifier "<<=" value
					;
	
/******************************
******************************/
value:				identifier
					| expression
					| integer
					| string
					;
					
identifier: 		IDENT
					| IN_ITER
					;

integer: 			INT_DEC
					| INT_HEX
					| INT_OCT
					| TRUE
					| FALSE
					;

string: 			STRING
					;

ip: 				integer '.' integer '.' integer '.' integer
					;

null: 				NULL
					;					
/******************************
		Compound commands
******************************/		 
compound: 				for_loop
						| foreach_loop
						| repeat_loop
						| while_loop
						| if_cond
						| block
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
						
while_loop:				WHILE '(' expression ')' block
						| WHILE '(' expression ')' command
						;
						
if_cond: 				IF '(' expression ')' block
						| IF '(' expression ')' command
						| IF '(' expression ')' block ELSE command
						| IF '(' expression ')' block ELSE block
						| IF '(' expression ')' command ELSE block
						| IF '(' expression ')' command ELSE command
						;

block: 					
						| '{' '}'
						| '{' line '}'
						| '{' argument_list '}'
						| '[' ']'
						| '[' argument_list ']'
						;
%%
#include <stdio.h>
extern char yytext[];
extern int column;
yyerror(char const *s)
{
	
	//printf("\n%d\n", yylineno);
	fflush(stdout);
	printf("\n%*s\n%*s\n", column, "^", column, s);
}

lex()
{
	printf("\n%s\n", stdin);
}
int main()
{
	return(yyparse());
}
