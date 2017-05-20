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
						| incr
						| decr
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

foreach_loop:
						;
						
repeat_loop:
						;
						
while_loop:				
						;
						
if_cond: 
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
