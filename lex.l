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

"until" { count(); return(UNTIL); }
"false" {count(); return(FALSE); }
"null" { count(); return(_NULL_); }
"true" { count(); return(TRUE); }
"FALSE" {count(); return(FALSE); }
"NULL" { count(); return(_NULL_); }
"TRUE" { count(); return(TRUE); }


[a-zA-Z_]+[_a-zA-Z0-9]* { count(); return(IDENT); }
([0-9]+|0[xX][a-fA-F0-9]+|[0][0-7]+) { count(); return(INT); }
(\"|\')([^\\"\'\r\n]|(\\.))*(\'|\") { count(); return(STRING); }
[ \f\n\t\v] { count(); }
"x" { count(); return(REP); }
"><" { count(); return(SUBSTR_EQ); }
">!<" { count(); return(SUBSTR_NEQ); }

"=~" { count(); return(REGEX_EQ); }
"!~" { count(); return(REGEX_NEQ); }

"==" { count(); return(CMP_EQ); }
"!=" { count(); return(CMP_NEQ); }
"<=" { count(); return(CMP_LE); }
">=" { count(); return(CMP_GE); }
"<" { count(); return('<'); }
">" { count(); return('>'); }

"=" {count(); return('='); }
"+=" { count(); return(ADD_ASS); }
"-=" { count(); return(SUB_ASS); }
"*=" { count(); return(MUL_ASS); }
"/=" { count(); return(DIV_ASS); }
"%=" { count(); return(MOD_ASS); }
">>=" { count(); return(SR_ASS); }
">>>=" { count(); return(SRR_ASS); }
"<<=" { count(); return(SL_ASS); }

"||" { count(); return(OR); }
"&&" { count(); return(AND); }
"!" { count(); return('!'); }

"|" { count(); return('|'); }
"^" { count(); return('^'); }
">>>" { count(); return(SRR); }
">>" { count(); return(SR); }
"<<" { count(); return(SL); }

"++" { count(); return(INC); }
"--" { count(); return(DEC); }

"**" { count(); return(POWER); }

"+" { count(); return('+'); }
"-" { count(); return('-'); }
"*" { count(); return('*'); }
"/" { count(); return('/'); }
"%" { count(); return('%'); }

"~" { count(); return('~'); }

"." { count(); return('.'); }
"," { count(); return(','); }
":" { count(); return(':'); }
";" { count(); return(';'); }
"(" { count(); return('('); }
")" { count(); return(')'); }
"[" { count(); return('['); }
"]" { count(); return(']'); }
"{" { count(); return('{'); }
"}" { count(); return('}'); }

"&" { count(); return('&'); }
"@" { count(); return('@'); }

[ \t\v\n\f] { count(); }



%%


int flag = 0;
int column = 0;
void count()
{
	int i;
	int j;
	if(flag == 0)
	{
		printf("%d||    ", yylineno);
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