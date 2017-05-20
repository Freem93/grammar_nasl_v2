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
%token NULL
%token TRUE

%token OR AND ADD_ASS SUB_ASS SUBSTR_EQ SUBSTR_NEQ REGEX_EQ REGEX_NEQ DEC INC DIV_ASS MUL_ASS MOD_ASS POWER

%token CMP_EQ CMP_GE CMP_LE CMP_NEQ SL SR SRR SRR_ASS SR_ASS SL_ASS
	
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
						| RETURN ';'
						;

/******************************
			Operations
******************************/
assign: 			identifier '=' value
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
value:				identifier
					| expression
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

null: 				NULL
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
						
/****************************
*****************************/
expression: 		'(' expression ')'
					| assign
					| inc_dec_exp
					| expr AND expr
					| '!' expr
					| expr OR expr
					| expr '+' expr
					| expr '-' expr
					| '-' expr 
					| expr '*' expr
					| expr POWER expr
					| expr '/' expr
					| expr '%' expr
					| expr '&' expr
					| expr '^' expr
					| expr '|' expr
					| expr SR expr
					| expr SL expr
					| expr SRR expr
					| inc_dec_exp
					| expr SUBSTR_EQ expr
					| expr SUBSTR_NEQ expr
					| expr REGEX_NEQ expr
					| expr REGEX_EQ expr
					| expr '<' expr
					| expr '>' expr
					| expr CMP_GE expr
					| expr CMP_LE expr
					| expr CMP_EQ expr
					| expr CMP_NEQ expr
					| call_function
					| block
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
