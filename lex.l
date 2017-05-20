%{
#include <stdio.h>
#include "y_tab.h"
void count();

%}

%option outfile="lex.yy.c"
%option noyywrap
%option yylineno


%%

[#].* { count(); return(COMMENT); }

"function" { count(); return(FUNCTION); }

"local_var" { count(); return(LOCAL); }
"global_var" { count(); return(GLOBAL); }

"else" { count(); return (ELSE); }
"if" { count(); return(IF); }

"include" { count(); return(INCLUDE); }
"export" { count(); return(EXPORT); }
"import" { count(); return(IMPORT); }

"return" { count(); return(RETURN); }
"break" { count(); return(BREAK); }
"continue" { count(); return(CONTINUE); }

"for" { count(); return(FOR); }
"foreach" { count(); return(FOREACH); }
"in" { count(); return(IN_ITER); }
"while" { count(); return(WHILE); }
"repeat" { count(); return(REPEAT); }
"x" { count(); return(REP); 
"until" { count(); return(UNTIL); }

[a-zA-Z_][_a-zA-Z0-9] { count(); return(IDENT); }
([0-9]+|0[xX][a-fA-F0-9]+|[0][0-7]+) { count(); return(INT); }
(\"|\')([^\\"\'\r\n]|(\\.))*(\'|\") { count(); return(STRING); }
[ \f\n\t\v] { count(); }

"><" { count(); return("><"); }
">!<" { count(); return(">!<"); }

"=~" { count(); return("=~"); }
"!~" { count(); return("!~"); }

"==" { count(); return("=="); }
"!=" { count(); return("!="); }
"<=" { count(); return("<="); }
">=" { count(); return(">="); }
"<" { count(); return("<"); }
">" { count(); return(">"); }

"=" {count(); return("="); }
"+=" { count(); return("+="); }
"-=" { count(); return("-="); }
"*=" { count(); return("*="); }
"/=" { count(); return("/="); }
"%=" { count(); return("%="); }
">>=" { count(); return(">>="); }
">>>=" { count(); return(">>>="); }
"<<=" { count(); return("<<="); }

"||" { count(); return("||"); }
"&&" { count(); return("&&"); }
"!" { count(); return("!"); }

"|" { count(); return("|"); }
"^" { count(); return("^"); }
">>>" { count(); return(">>>"); }
">>" { count(); return(">>"); }
"<<" { count(); return("<<"); }

"++" { count(); return("++"); }
"--" { count(); return("--"); }

"**" { count(); return("**"); }

"+" { count(); return("+"); }
"-" { count(); return("-"); }
"*" { count(); return("*"); }
"/" { count(); return("/"); }
"%" { count(); return("%"); }

"~" { count(); return("~"); }

"." { count(); return("."); }
"," { count(); return(","); }
":" { count(); return(":"); }
";" { count(); return(";"); }
"(" { count(); return("("); }
")" { count(); return(")"); }
"[" { count(); return("["); }
"]" { count(); return("]"); }
"{" { count(); return("{"); }
"}" { count(); return("}"); }

"&" { count(); return("&"); }
"@" { count(); return("@"); }

[ \t\v\n\f] { count(); }

"FALSE" {count(); return(FALSE); }
"NULL" { count(); return(NULL); }
"TRUE" { count(); return(TRUE); }

%%


int flag = 0;
int column = 0;
void count()
{
	int i;
	int j;
	if(flag == 0)
	{
		printf("%d||	", yylineno);
		flag = 1;
	}		
	ECHO;
	for (i = 0; yytext[i] != '\0'; i++)
		if (yytext[i] == '\n'){
			column = 0;
			printf("%d||	", yylineno);
			
		}
			
		else if (yytext[i] == '\t')
			column += 8 - (column % 8);
		else
			column++;
}
