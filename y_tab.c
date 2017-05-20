
/*  A Bison parser, made from nasl_grammar.y with Bison version GNU Bison version 1.24
  */

#define YYBISON 1  /* Identify Bison output.  */

#define	COMMENT	258
#define	FUNCTION	259
#define	LOCAL	260
#define	GLOBAL	261
#define	ELSE	262
#define	IF	263
#define	INCLUDE	264
#define	EXPORT	265
#define	IMPORT	266
#define	RETURN	267
#define	BREAK	268
#define	CONTINUE	269
#define	FOR	270
#define	FOREACH	271
#define	IN_ITER	272
#define	WHILE	273
#define	REPEAT	274
#define	REP	275
#define	UNTIL	276
#define	IDENT	277
#define	INT	278
#define	STRING	279
#define	FALSE	280
#define	NULL	281
#define	TRUE	282
#define	OR	283
#define	AND	284
#define	ADD_ASS	285
#define	SUB_ASS	286
#define	SUBSTR_EQ	287
#define	SUBSTR_NEQ	288
#define	REGEX_EQ	289
#define	REGEX_NEQ	290
#define	DEC	291
#define	INC	292
#define	DIV_ASS	293
#define	MUL_ASS	294
#define	MOD_ASS	295
#define	POWER	296
#define	CMP_EQ	297
#define	CMP_GE	298
#define	CMP_LE	299
#define	CMP_NEQ	300
#define	SL	301
#define	SR	302
#define	SRR	303
#define	SRR_ASS	304
#define	SR_ASS	305
#define	SL_ASS	306

#line 1 "nasl_grammar.y"


#define YYERROR_VERBOSE 1
#define YYDEBUG 1
extern int yylineno;

#ifndef YYLTYPE
typedef
  struct yyltype
    {
      int timestamp;
      int first_line;
      int first_column;
      int last_line;
      int last_column;
      char *text;
   }
  yyltype;

#define YYLTYPE yyltype
#endif

#ifndef YYSTYPE
#define YYSTYPE int
#endif
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		260
#define	YYFLAG		-32768
#define	YYNTBASE	75

#define YYTRANSLATE(x) ((unsigned)(x) <= 306 ? yytranslate[x] : 116)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    65,     2,     2,     2,    70,    55,     2,    52,
    53,    68,    66,    54,    67,    59,    69,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    64,    57,    73,
    58,    74,     2,    56,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
    62,     2,    63,    71,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    60,    72,    61,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     2,     3,     4,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
    26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
    36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
    46,    47,    48,    49,    50,    51
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     3,     4,     6,     8,    10,    12,    15,    22,    28,
    32,    34,    36,    39,    41,    43,    45,    47,    49,    51,
    53,    55,    57,    59,    61,    63,    65,    67,    69,    71,
    73,    78,    83,    86,    89,    91,    93,    96,    99,   103,
   108,   112,   116,   120,   122,   124,   127,   130,   133,   136,
   140,   144,   148,   152,   156,   160,   164,   168,   170,   172,
   174,   176,   178,   180,   182,   184,   192,   194,   197,   199,
   201,   203,   205,   207,   217,   227,   234,   241,   249,   257,
   263,   269,   275,   281,   287,   293,   301,   309,   317,   325,
   326,   329,   333,   337,   340,   344,   348,   352,   354,   358,
   360,   364,   366,   370,   374,   378,   382,   386,   390,   392,
   394,   398,   402,   405,   409,   413,   417,   420,   424,   428,
   432,   436,   440,   444,   448,   452,   456,   460,   464,   468,
   472,   476,   480,   484,   488,   492,   496,   500,   502,   504,
   506
};

static const short yyrhs[] = {    76,
    75,     0,     0,     3,     0,    77,     0,    78,     0,    81,
     0,    10,    78,     0,     4,    98,    52,    79,    53,   110,
     0,     4,    98,    52,    53,   110,     0,    80,    54,    79,
     0,    80,     0,    98,     0,    55,    98,     0,    93,     0,
    82,     0,   104,     0,    93,     0,    92,     0,    83,     0,
    84,     0,    87,     0,    90,     0,    89,     0,    94,     0,
    91,     0,    85,     0,    86,     0,    88,     0,    13,     0,
    14,     0,    11,    52,   100,    53,     0,     9,    52,   100,
    53,     0,    12,   115,     0,    12,    56,     0,    12,     0,
    57,     0,     6,   112,     0,     5,   112,     0,    92,    20,
   115,     0,    98,    52,    79,    53,     0,    98,    52,    53,
     0,    98,    58,    97,     0,    98,    58,   103,     0,    95,
     0,    96,     0,    37,    98,     0,    36,    98,     0,    98,
    37,     0,    98,    36,     0,    98,    30,    97,     0,    98,
    31,    97,     0,    98,    39,    97,     0,    98,    38,    97,
     0,    98,    40,    97,     0,    98,    50,    97,     0,    98,
    49,    97,     0,    98,    51,    97,     0,   115,     0,    92,
     0,    22,     0,    17,     0,    23,     0,    27,     0,    25,
     0,    24,     0,    99,    59,    99,    59,    99,    59,    99,
     0,    26,     0,    56,    22,     0,   105,     0,   106,     0,
   107,     0,   108,     0,   109,     0,    15,    52,   115,    57,
   115,    57,   115,    53,   110,     0,    15,    52,   115,    57,
   115,    57,   115,    53,    81,     0,    16,    98,    52,   115,
    53,   110,     0,    16,    98,    52,   115,    53,    81,     0,
    16,    52,    98,    17,   115,    53,   110,     0,    16,    52,
    98,    17,   115,    53,    81,     0,    19,   110,    21,   115,
    57,     0,    19,    81,    21,   115,    57,     0,    18,    52,
   115,    53,   110,     0,    18,    52,   115,    53,    81,     0,
     8,    52,   115,    53,   110,     0,     8,    52,   115,    53,
    81,     0,     8,    52,   115,    53,   110,     7,    81,     0,
     8,    52,   115,    53,   110,     7,   110,     0,     8,    52,
   115,    53,    81,     7,   110,     0,     8,    52,   115,    53,
    81,     7,    81,     0,     0,    60,    61,     0,    60,    76,
    61,     0,    60,   113,    61,     0,    62,    63,     0,    62,
   113,    63,     0,    98,    58,   115,     0,    98,    58,   103,
     0,    98,     0,   111,    54,   112,     0,   111,     0,   113,
    54,   114,     0,   114,     0,   100,    64,   115,     0,    99,
    64,   115,     0,   100,    64,   103,     0,    99,    64,   103,
     0,    98,    64,   115,     0,    98,    64,   103,     0,   115,
     0,   103,     0,    52,   115,    53,     0,   115,    29,   115,
     0,    65,   115,     0,   115,    28,   115,     0,   115,    66,
   115,     0,   115,    67,   115,     0,    67,   115,     0,   115,
    68,   115,     0,   115,    41,   115,     0,   115,    69,   115,
     0,   115,    70,   115,     0,   115,    55,   115,     0,   115,
    71,   115,     0,   115,    72,   115,     0,   115,    47,   115,
     0,   115,    46,   115,     0,   115,    48,   115,     0,   115,
    32,   115,     0,   115,    33,   115,     0,   115,    35,   115,
     0,   115,    34,   115,     0,   115,    73,   115,     0,   115,
    74,   115,     0,   115,    43,   115,     0,   115,    44,   115,
     0,   115,    42,   115,     0,   115,    45,   115,     0,    99,
     0,   100,     0,   101,     0,   102,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
    51,    52,    57,    58,    59,    60,    67,    70,    71,    77,
    78,    81,    82,    83,    88,    89,    94,    95,    96,    97,
    98,    99,   100,   101,   102,   103,   104,   105,   112,   115,
   118,   121,   124,   125,   126,   129,   132,   135,   138,   141,
   142,   147,   148,   149,   150,   153,   154,   155,   156,   159,
   160,   161,   162,   163,   166,   167,   168,   173,   174,   177,
   178,   181,   182,   183,   186,   189,   192,   195,   200,   201,
   202,   203,   204,   210,   211,   214,   215,   216,   217,   220,
   221,   224,   225,   228,   229,   230,   231,   232,   233,   236,
   237,   238,   239,   240,   241,   248,   249,   250,   253,   254,
   257,   258,   261,   262,   263,   264,   265,   266,   267,   268,
   273,   274,   275,   276,   277,   278,   279,   280,   281,   282,
   283,   284,   285,   286,   287,   288,   289,   290,   291,   292,
   293,   294,   295,   296,   297,   298,   299,   300,   301,   302,
   303
};

static const char * const yytname[] = {   "$","error","$undefined.","COMMENT",
"FUNCTION","LOCAL","GLOBAL","ELSE","IF","INCLUDE","EXPORT","IMPORT","RETURN",
"BREAK","CONTINUE","FOR","FOREACH","IN_ITER","WHILE","REPEAT","REP","UNTIL",
"IDENT","INT","STRING","FALSE","NULL","TRUE","OR","AND","ADD_ASS","SUB_ASS",
"SUBSTR_EQ","SUBSTR_NEQ","REGEX_EQ","REGEX_NEQ","DEC","INC","DIV_ASS","MUL_ASS",
"MOD_ASS","POWER","CMP_EQ","CMP_GE","CMP_LE","CMP_NEQ","SL","SR","SRR","SRR_ASS",
"SR_ASS","SL_ASS","'('","')'","','","'&'","'@'","';'","'='","'.'","'{'","'}'",
"'['","']'","':'","'!'","'+'","'-'","'*'","'/'","'%'","'^'","'|'","'<'","'>'",
"nasl_script","line","export","function","parameters","parameter","command",
"simple","break","continue","import","include","return","empty","global","local",
"rep","call_function","assign","inc_dec_exp","assign_math_op","assign_shift_op",
"value","identifier","integer","string","ip","null","ref","compound","for_loop",
"foreach_loop","repeat_loop","while_loop","if_cond","block","var","vars","argument_list",
"argument","expression",""
};
#endif

static const short yyr1[] = {     0,
    75,    75,    76,    76,    76,    76,    77,    78,    78,    79,
    79,    80,    80,    80,    81,    81,    82,    82,    82,    82,
    82,    82,    82,    82,    82,    82,    82,    82,    83,    84,
    85,    86,    87,    87,    87,    88,    89,    90,    91,    92,
    92,    93,    93,    93,    93,    94,    94,    94,    94,    95,
    95,    95,    95,    95,    96,    96,    96,    97,    97,    98,
    98,    99,    99,    99,   100,   101,   102,   103,   104,   104,
   104,   104,   104,   105,   105,   106,   106,   106,   106,   107,
   107,   108,   108,   109,   109,   109,   109,   109,   109,   110,
   110,   110,   110,   110,   110,   111,   111,   111,   112,   112,
   113,   113,   114,   114,   114,   114,   114,   114,   114,   114,
   115,   115,   115,   115,   115,   115,   115,   115,   115,   115,
   115,   115,   115,   115,   115,   115,   115,   115,   115,   115,
   115,   115,   115,   115,   115,   115,   115,   115,   115,   115,
   115
};

static const short yyr2[] = {     0,
     2,     0,     1,     1,     1,     1,     2,     6,     5,     3,
     1,     1,     2,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
     4,     4,     2,     2,     1,     1,     2,     2,     3,     4,
     3,     3,     3,     1,     1,     2,     2,     2,     2,     3,
     3,     3,     3,     3,     3,     3,     3,     1,     1,     1,
     1,     1,     1,     1,     1,     7,     1,     2,     1,     1,
     1,     1,     1,     9,     9,     6,     6,     7,     7,     5,
     5,     5,     5,     5,     5,     7,     7,     7,     7,     0,
     2,     3,     3,     2,     3,     3,     3,     1,     3,     1,
     3,     1,     3,     3,     3,     3,     3,     3,     1,     1,
     3,     3,     2,     3,     3,     3,     2,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     1,     1,     1,
     1
};

static const short yydefact[] = {     2,
     3,     0,     0,     0,     0,     0,     0,     0,    35,    29,
    30,     0,     0,    61,     0,    90,    60,     0,     0,    36,
     2,     4,     5,     6,    15,    19,    20,    26,    27,    21,
    28,    23,    22,    25,    18,    17,    24,    44,    45,     0,
    16,    69,    70,    71,    72,    73,     0,    98,   100,    38,
    37,     0,     0,     7,     0,    62,    65,    64,    67,    63,
     0,    34,     0,     0,   138,   139,   140,   141,    33,     0,
     0,     0,     0,     0,     0,     0,     0,    47,    46,     1,
     0,     0,     0,    49,    48,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
   113,   117,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,    91,     0,     0,   138,   139,   110,     0,   102,
   109,    94,     0,     0,     0,     0,    39,    59,    50,     0,
    58,    51,    53,    52,    54,    56,    55,    57,    41,     0,
     0,    11,    14,    12,    42,    43,    90,     0,    97,    96,
    99,    90,    32,    31,   111,     0,   114,   112,   128,   129,
   131,   130,   119,   136,   134,   135,   137,   126,   125,   127,
   122,   115,   116,   118,   120,   121,   123,   124,   132,   133,
     0,     0,     0,    90,    68,    92,     0,     0,     0,     0,
    93,    95,     0,     0,    13,    40,     0,     9,    90,    85,
    84,     0,     0,     0,    90,    83,    82,   108,   107,   106,
   104,   105,   103,   101,    81,    80,    10,     8,    90,    90,
     0,     0,    90,    77,    76,    89,    88,    86,    87,     0,
     0,    79,    78,    66,    90,    75,    74,     0,     0,     0
};

static const short yydefgoto[] = {    80,
    21,    22,    23,   161,   162,    24,    25,    26,    27,    28,
    29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
    39,   149,    40,    65,    66,    67,    68,   138,    41,    42,
    43,    44,    45,    46,    77,    49,    50,   139,   140,   151
};

static const short yypact[] = {   345,
-32768,     8,     8,     8,   -25,   -23,     5,   -15,   840,-32768,
-32768,    -6,    -5,-32768,     6,   309,-32768,     8,     8,-32768,
   345,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,    37,-32768,-32768,-32768,-32768,   896,
-32768,-32768,-32768,-32768,-32768,-32768,    11,   -39,    -9,-32768,
-32768,    25,    40,-32768,    40,-32768,-32768,-32768,-32768,-32768,
    25,-32768,    25,    25,    10,-32768,-32768,-32768,   814,    25,
     8,    19,    25,   246,    16,    53,    59,-32768,-32768,-32768,
    25,   267,   267,-32768,-32768,   267,   267,   267,   267,   267,
   267,    72,   154,   150,   847,     8,   344,    29,    31,   391,
   814,   814,     9,    25,    25,    25,    25,    25,    25,    25,
    25,    25,    25,    25,    25,    25,    25,    25,    25,    25,
    25,    25,    25,    25,    25,    25,    25,   438,    61,    25,
   485,    63,-32768,    27,   879,   -33,    22,-32768,   -43,-32768,
   814,-32768,    60,   -49,    25,    25,   814,-32768,-32768,    39,
   814,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,     8,
    42,    67,-32768,   911,-32768,-32768,   -47,    70,-32768,   814,
-32768,   309,-32768,-32768,-32768,    34,   814,   814,   814,   814,
   814,   814,   814,   814,   814,   814,   814,   814,   814,   814,
   814,   814,   814,   814,   814,   814,   814,   814,   814,   814,
    25,    25,   532,   309,-32768,-32768,   847,   847,   847,   154,
-32768,-32768,   579,   626,-32768,-32768,    -1,-32768,   -47,   122,
   123,     9,   673,   720,   309,-32768,-32768,-32768,   814,-32768,
   814,-32768,   814,-32768,-32768,-32768,-32768,-32768,   309,   309,
    82,    25,   309,-32768,-32768,-32768,-32768,-32768,-32768,     9,
   767,-32768,-32768,-32768,   309,-32768,-32768,   152,   155,-32768
};

static const short yypgoto[] = {   157,
    84,-32768,   156,   -91,-32768,   -16,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,   884,   -84,-32768,-32768,
-32768,   250,    57,   -68,   -51,-32768,-32768,   -73,-32768,-32768,
-32768,-32768,-32768,-32768,    -7,-32768,    24,    86,   -48,    -8
};


#define	YYLAST		977


static const short yytable[] = {    76,
    69,    98,   168,    99,   210,   136,   136,   163,     2,   163,
   210,    14,    74,   212,    75,    14,    17,   211,    95,   166,
    17,   169,   137,   137,    14,   103,    52,    51,    53,    17,
   208,    56,    14,    58,   176,    60,    55,    17,    56,    57,
    58,    59,    60,    97,    96,    70,    71,    56,    57,    58,
    59,    60,   100,   160,   101,   102,    81,    73,    47,    48,
    48,   128,    94,    57,   131,   141,   141,    61,   103,    72,
   130,   132,   147,   145,    78,    79,    61,   202,   142,   146,
    63,   173,    64,   174,   205,   209,   170,   206,    14,    63,
    92,    64,   222,    17,   216,   177,   178,   179,   180,   181,
   182,   183,   184,   185,   186,   187,   188,   189,   190,   191,
   192,   193,   194,   195,   196,   197,   198,   199,   200,   171,
   217,   203,   219,   207,   159,   237,   160,   129,   239,   240,
   135,   143,   163,   228,   230,   232,   213,   214,   150,   150,
   250,   136,   150,   150,   150,   150,   150,   150,   164,   150,
   164,   259,    48,   241,   260,   220,   258,   134,   137,   218,
   144,   234,    54,     0,   221,     0,    14,     0,     0,     0,
    14,    17,     0,     0,     0,    17,    56,    57,    58,    59,
    60,   254,     0,     0,     0,     0,     0,   226,     0,     0,
     0,     0,   223,   224,     0,     0,   227,     0,   229,   231,
   233,   141,   167,     0,   160,    61,     0,     0,   244,   132,
     0,   238,     0,     0,     0,     0,   215,   245,    63,     0,
    64,     0,   246,   248,     0,     0,   252,     0,     0,     0,
     0,   247,   249,   251,     0,   253,     0,     0,   256,     0,
     0,     0,     0,     0,     0,     0,     0,   257,     1,     2,
     3,     4,     0,     5,     6,     7,     8,     9,    10,    11,
    12,    13,    14,    15,    16,     0,   143,    17,    56,    57,
    58,    59,    60,   164,     0,     0,     0,     0,     0,     0,
     0,    18,    19,    14,     0,     0,     0,     0,    17,    56,
    57,    58,    59,    60,     0,     0,     0,    61,     0,     0,
     0,   132,    20,     0,     0,     0,   133,     0,     0,     0,
    63,     0,    64,     3,     4,     0,     5,     6,    61,     8,
     9,    10,    11,    12,    13,    14,    15,    16,     0,     0,
    17,    63,   152,    64,     0,   153,   154,   155,   156,   157,
   158,     0,   165,     0,    18,    19,     0,     1,     2,     3,
     4,     0,     5,     6,     7,     8,     9,    10,    11,    12,
    13,    14,    15,    16,     0,    20,    17,     0,    74,     0,
    75,   104,   105,     0,     0,   106,   107,   108,   109,     0,
    18,    19,     0,     0,   110,   111,   112,   113,   114,   115,
   116,   117,     0,     0,     0,     0,   172,     0,   118,     0,
     0,    20,     0,     0,     0,     0,     0,     0,     0,   119,
   120,   121,   122,   123,   124,   125,   126,   127,   104,   105,
     0,     0,   106,   107,   108,   109,     0,     0,     0,     0,
     0,   110,   111,   112,   113,   114,   115,   116,   117,     0,
     0,     0,     0,   175,     0,   118,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,   119,   120,   121,   122,
   123,   124,   125,   126,   127,   104,   105,     0,     0,   106,
   107,   108,   109,     0,     0,     0,     0,     0,   110,   111,
   112,   113,   114,   115,   116,   117,     0,     0,     0,     0,
     0,     0,   118,     0,   201,     0,     0,     0,     0,     0,
     0,     0,     0,   119,   120,   121,   122,   123,   124,   125,
   126,   127,   104,   105,     0,     0,   106,   107,   108,   109,
     0,     0,     0,     0,     0,   110,   111,   112,   113,   114,
   115,   116,   117,     0,     0,     0,     0,   204,     0,   118,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
   119,   120,   121,   122,   123,   124,   125,   126,   127,   104,
   105,     0,     0,   106,   107,   108,   109,     0,     0,     0,
     0,     0,   110,   111,   112,   113,   114,   115,   116,   117,
     0,     0,     0,     0,   225,     0,   118,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,   119,   120,   121,
   122,   123,   124,   125,   126,   127,   104,   105,     0,     0,
   106,   107,   108,   109,     0,     0,     0,     0,     0,   110,
   111,   112,   113,   114,   115,   116,   117,     0,     0,     0,
     0,     0,     0,   118,     0,   235,     0,     0,     0,     0,
     0,     0,     0,     0,   119,   120,   121,   122,   123,   124,
   125,   126,   127,   104,   105,     0,     0,   106,   107,   108,
   109,     0,     0,     0,     0,     0,   110,   111,   112,   113,
   114,   115,   116,   117,     0,     0,     0,     0,     0,     0,
   118,     0,   236,     0,     0,     0,     0,     0,     0,     0,
     0,   119,   120,   121,   122,   123,   124,   125,   126,   127,
   104,   105,     0,     0,   106,   107,   108,   109,     0,     0,
     0,     0,     0,   110,   111,   112,   113,   114,   115,   116,
   117,     0,     0,     0,     0,     0,     0,   118,     0,   242,
     0,     0,     0,     0,     0,     0,     0,     0,   119,   120,
   121,   122,   123,   124,   125,   126,   127,   104,   105,     0,
     0,   106,   107,   108,   109,     0,     0,     0,     0,     0,
   110,   111,   112,   113,   114,   115,   116,   117,     0,     0,
     0,     0,   243,     0,   118,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,   119,   120,   121,   122,   123,
   124,   125,   126,   127,   104,   105,     0,     0,   106,   107,
   108,   109,     0,     0,     0,     0,     0,   110,   111,   112,
   113,   114,   115,   116,   117,     0,     0,     0,     0,   255,
     0,   118,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,   119,   120,   121,   122,   123,   124,   125,   126,
   127,   104,   105,     0,     0,   106,   107,   108,   109,     0,
     0,     0,     0,     0,   110,   111,   112,   113,   114,   115,
   116,   117,    56,    57,    58,    59,    60,     0,   118,    56,
    57,    58,    59,    60,     0,     0,     0,     0,     0,   119,
   120,   121,   122,   123,   124,   125,   126,   127,     0,     0,
     0,    61,     0,     0,     0,    62,     0,     0,    61,     0,
     0,     0,   132,     0,    63,     0,    64,     0,    82,    83,
     0,    63,     0,    64,    84,    85,    86,    87,    88,     0,
     0,     0,     0,     0,     0,    82,    83,    89,    90,    91,
    92,    84,    85,    86,    87,    88,    93,     0,     0,     0,
    82,    83,   207,     0,    89,    90,    91,    92,    86,    87,
    88,     0,     0,    93,     0,     0,     0,     0,     0,    89,
    90,    91,     0,     0,     0,   148,   148,     0,    93,   148,
   148,   148,   148,   148,   148,     0,   148
};

static const short yycheck[] = {    16,
     9,    53,    94,    55,    54,    74,    75,    92,     4,    94,
    54,    17,    60,    63,    62,    17,    22,    61,    58,    93,
    22,    95,    74,    75,    17,    59,    52,     4,    52,    22,
    64,    23,    17,    25,   103,    27,    52,    22,    23,    24,
    25,    26,    27,    52,    54,    52,    52,    23,    24,    25,
    26,    27,    61,    55,    63,    64,    20,    52,     2,     3,
     4,    70,    52,    24,    73,    74,    75,    52,    59,    13,
    52,    56,    81,    21,    18,    19,    52,    17,    63,    21,
    65,    53,    67,    53,    22,    64,    95,    61,    17,    65,
    52,    67,    59,    22,    53,   104,   105,   106,   107,   108,
   109,   110,   111,   112,   113,   114,   115,   116,   117,   118,
   119,   120,   121,   122,   123,   124,   125,   126,   127,    96,
    54,   130,    53,    64,    53,   217,    55,    71,     7,     7,
    74,    75,   217,   207,   208,   209,   145,   146,    82,    83,
    59,   210,    86,    87,    88,    89,    90,    91,    92,    93,
    94,     0,    96,   222,     0,   172,     0,    74,   210,   167,
    75,   210,     7,    -1,   172,    -1,    17,    -1,    -1,    -1,
    17,    22,    -1,    -1,    -1,    22,    23,    24,    25,    26,
    27,   250,    -1,    -1,    -1,    -1,    -1,   204,    -1,    -1,
    -1,    -1,   201,   202,    -1,    -1,   204,    -1,   207,   208,
   209,   210,    53,    -1,    55,    52,    -1,    -1,   225,    56,
    -1,   219,    -1,    -1,    -1,    -1,   160,   225,    65,    -1,
    67,    -1,   239,   240,    -1,    -1,   243,    -1,    -1,    -1,
    -1,   239,   240,   242,    -1,   243,    -1,    -1,   255,    -1,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,   255,     3,     4,
     5,     6,    -1,     8,     9,    10,    11,    12,    13,    14,
    15,    16,    17,    18,    19,    -1,   210,    22,    23,    24,
    25,    26,    27,   217,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    36,    37,    17,    -1,    -1,    -1,    -1,    22,    23,
    24,    25,    26,    27,    -1,    -1,    -1,    52,    -1,    -1,
    -1,    56,    57,    -1,    -1,    -1,    61,    -1,    -1,    -1,
    65,    -1,    67,     5,     6,    -1,     8,     9,    52,    11,
    12,    13,    14,    15,    16,    17,    18,    19,    -1,    -1,
    22,    65,    83,    67,    -1,    86,    87,    88,    89,    90,
    91,    -1,    93,    -1,    36,    37,    -1,     3,     4,     5,
     6,    -1,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    -1,    57,    22,    -1,    60,    -1,
    62,    28,    29,    -1,    -1,    32,    33,    34,    35,    -1,
    36,    37,    -1,    -1,    41,    42,    43,    44,    45,    46,
    47,    48,    -1,    -1,    -1,    -1,    53,    -1,    55,    -1,
    -1,    57,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    66,
    67,    68,    69,    70,    71,    72,    73,    74,    28,    29,
    -1,    -1,    32,    33,    34,    35,    -1,    -1,    -1,    -1,
    -1,    41,    42,    43,    44,    45,    46,    47,    48,    -1,
    -1,    -1,    -1,    53,    -1,    55,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    -1,    66,    67,    68,    69,
    70,    71,    72,    73,    74,    28,    29,    -1,    -1,    32,
    33,    34,    35,    -1,    -1,    -1,    -1,    -1,    41,    42,
    43,    44,    45,    46,    47,    48,    -1,    -1,    -1,    -1,
    -1,    -1,    55,    -1,    57,    -1,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    66,    67,    68,    69,    70,    71,    72,
    73,    74,    28,    29,    -1,    -1,    32,    33,    34,    35,
    -1,    -1,    -1,    -1,    -1,    41,    42,    43,    44,    45,
    46,    47,    48,    -1,    -1,    -1,    -1,    53,    -1,    55,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    66,    67,    68,    69,    70,    71,    72,    73,    74,    28,
    29,    -1,    -1,    32,    33,    34,    35,    -1,    -1,    -1,
    -1,    -1,    41,    42,    43,    44,    45,    46,    47,    48,
    -1,    -1,    -1,    -1,    53,    -1,    55,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,    66,    67,    68,
    69,    70,    71,    72,    73,    74,    28,    29,    -1,    -1,
    32,    33,    34,    35,    -1,    -1,    -1,    -1,    -1,    41,
    42,    43,    44,    45,    46,    47,    48,    -1,    -1,    -1,
    -1,    -1,    -1,    55,    -1,    57,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    66,    67,    68,    69,    70,    71,
    72,    73,    74,    28,    29,    -1,    -1,    32,    33,    34,
    35,    -1,    -1,    -1,    -1,    -1,    41,    42,    43,    44,
    45,    46,    47,    48,    -1,    -1,    -1,    -1,    -1,    -1,
    55,    -1,    57,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    66,    67,    68,    69,    70,    71,    72,    73,    74,
    28,    29,    -1,    -1,    32,    33,    34,    35,    -1,    -1,
    -1,    -1,    -1,    41,    42,    43,    44,    45,    46,    47,
    48,    -1,    -1,    -1,    -1,    -1,    -1,    55,    -1,    57,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    66,    67,
    68,    69,    70,    71,    72,    73,    74,    28,    29,    -1,
    -1,    32,    33,    34,    35,    -1,    -1,    -1,    -1,    -1,
    41,    42,    43,    44,    45,    46,    47,    48,    -1,    -1,
    -1,    -1,    53,    -1,    55,    -1,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    66,    67,    68,    69,    70,
    71,    72,    73,    74,    28,    29,    -1,    -1,    32,    33,
    34,    35,    -1,    -1,    -1,    -1,    -1,    41,    42,    43,
    44,    45,    46,    47,    48,    -1,    -1,    -1,    -1,    53,
    -1,    55,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    -1,    66,    67,    68,    69,    70,    71,    72,    73,
    74,    28,    29,    -1,    -1,    32,    33,    34,    35,    -1,
    -1,    -1,    -1,    -1,    41,    42,    43,    44,    45,    46,
    47,    48,    23,    24,    25,    26,    27,    -1,    55,    23,
    24,    25,    26,    27,    -1,    -1,    -1,    -1,    -1,    66,
    67,    68,    69,    70,    71,    72,    73,    74,    -1,    -1,
    -1,    52,    -1,    -1,    -1,    56,    -1,    -1,    52,    -1,
    -1,    -1,    56,    -1,    65,    -1,    67,    -1,    30,    31,
    -1,    65,    -1,    67,    36,    37,    38,    39,    40,    -1,
    -1,    -1,    -1,    -1,    -1,    30,    31,    49,    50,    51,
    52,    36,    37,    38,    39,    40,    58,    -1,    -1,    -1,
    30,    31,    64,    -1,    49,    50,    51,    52,    38,    39,
    40,    -1,    -1,    58,    -1,    -1,    -1,    -1,    -1,    49,
    50,    51,    -1,    -1,    -1,    82,    83,    -1,    58,    86,
    87,    88,    89,    90,    91,    -1,    93
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "bison.simple"

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */
   
#ifndef alloca
#ifdef __GNUC__
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi)
#include <alloca.h>
#else /* not sparc */
#if defined (MSDOS) && !defined (__TURBOC__)
#include <malloc.h>
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
#include <malloc.h>
 #pragma alloca
#else /* not MSDOS, __TURBOC__, or _AIX */
#ifdef __hpux
#ifdef __cplusplus
extern "C" {
void *alloca (unsigned int);
};
#else /* not __cplusplus */
void *alloca ();
#endif /* not __cplusplus */
#endif /* __hpux */
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc.  */
#endif /* not GNU C.  */
#endif /* alloca not defined.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	return(0)
#define YYABORT 	return(1)
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
int yyparse (void);
#endif

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(FROM,TO,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (from, to, count)
     char *from;
     char *to;
     int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *from, char *to, int count)
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 192 "bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#else
#define YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#endif

int
yyparse(YYPARSE_PARAM)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
      yyss = (short *) alloca (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss1, (char *)yyss, size * sizeof (*yyssp));
      yyvs = (YYSTYPE *) alloca (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs1, (char *)yyvs, size * sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) alloca (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls1, (char *)yyls, size * sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

}
   /* the action file gets copied in in place of this dollarsign */
#line 487 "bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;
}
#line 305 "nasl_grammar.y"

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
