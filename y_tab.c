
/*  A Bison parser, made from nasl_grammar.y with Bison version GNU Bison version 1.24
  */

#define YYBISON 1  /* Identify Bison output.  */

#define	FUNCTION	258
#define	EQ	259
#define	NE	260
#define	LT	261
#define	GT	262
#define	LE	263
#define	GE	264
#define	SEARCH_SUBSTR	265
#define	NOT_SEARCH_SUBSTR	266
#define	POWER	267
#define	ADD	268
#define	SUB	269
#define	MUL	270
#define	DIV	271
#define	MOD	272
#define	XOR	273
#define	OR	274
#define	OR_OP	275
#define	IF	276
#define	ELSE	277
#define	FOR	278
#define	FOREACH	279
#define	WHILE	280
#define	REPEAT	281
#define	UNTIL	282
#define	BREAK	283
#define	CONTINUE	284
#define	RETURN	285
#define	INCLUDE	286
#define	STR_FIRST	287
#define	ASSIGN	288
#define	RIGHT_ASSIGN	289
#define	RIGHT_RIGHT_ASSIGN	290
#define	LEFT_ASSIGN	291
#define	ADD_ASSIGN	292
#define	SUB_ASSIGN	293
#define	MUL_ASSIGN	294
#define	DIV_ASSIGN	295
#define	MOD_ASSIGN	296
#define	AND_ASSIGN	297
#define	XOR_ASSIGN	298
#define	OR_ASSIGN	299
#define	RIGHT_OP	300
#define	RIGHT_OP_3	301
#define	LEFT_OP	302
#define	INC_OP	303
#define	DEC_OP	304
#define	AND_OP	305
#define	AND	306
#define	SEMICOLON	307
#define	LEFT_BRACE	308
#define	RIGHT_BRACE	309
#define	COMMA	310
#define	COLON	311
#define	LEFT_PARENTHESIS	312
#define	RIGHT_PARENTHESIS	313
#define	LEFT_SQ_BRACKET	314
#define	RIGHT_SQ_BRACKET	315
#define	NOT	316
#define	BIT	317
#define	NOT_BIT	318
#define	ARROW	319
#define	ASSIGN_BIT	320
#define	INTEGER	321
#define	IF_1	322
#define	IDENTIFIER	323
#define	POINT	324
#define	LOCAL	325
#define	GLOBAL	326
#define	COMMENT	327
#define	IN_ITER	328
#define	UPLUS	329
#define	UMINUS	330
#define	EXPORT	331
#define	IMPORT	332
#define	REFERENCE	333

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



#define	YYFINAL		278
#define	YYFLAG		-32768
#define	YYNTBASE	79

#define YYTRANSLATE(x) ((unsigned)(x) <= 333 ? yytranslate[x] : 125)

static const char yytranslate[] = {     0,
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
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     2,     3,     4,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
    26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
    36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
    46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
    56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
    66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
    76,    77,    78
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     3,     5,     8,    10,    12,    19,    20,    22,
    24,    28,    31,    36,    40,    46,    50,    53,    56,    60,
    64,    65,    67,    71,    72,    74,    78,    82,    86,    89,
    91,    93,    95,    97,    99,   102,   104,   106,   108,   110,
   113,   116,   118,   121,   124,   127,   130,   133,   136,   139,
   141,   147,   155,   157,   159,   161,   163,   173,   182,   188,
   194,   201,   209,   210,   212,   214,   216,   221,   223,   225,
   230,   235,   236,   238,   240,   244,   246,   250,   254,   258,
   262,   266,   270,   274,   278,   282,   286,   288,   290,   292,
   297,   299,   302,   305,   308,   311,   314,   317,   321,   325,
   328,   332,   336,   340,   343,   347,   351,   355,   359,   363,
   367,   371,   375,   377,   381,   385,   389,   393,   397,   401,
   405,   409,   413,   417,   421,   425,   427,   429,   431,   433,
   435,   437,   441,   443,   447,   449,   453,   455,   457,   459,
   461,   463,   465,   467,   475,   478
};

static const short yyrhs[] = {    -1,
    80,     0,    81,     0,    81,    80,     0,    93,     0,    82,
     0,     3,    68,    57,    83,    58,    85,     0,     0,    84,
     0,   110,     0,   110,    55,    84,     0,    51,   110,     0,
    51,   110,    55,    84,     0,   109,    33,   114,     0,   109,
    33,   114,    55,    84,     0,    53,    92,    54,     0,    53,
    54,     0,    93,    22,     0,    53,    88,    54,     0,    59,
    87,    60,     0,     0,    90,     0,    87,    55,    90,     0,
     0,    89,     0,    88,    55,    89,     0,    91,    56,    91,
     0,    91,    56,   104,     0,    59,    60,     0,   104,     0,
    66,     0,    32,     0,   110,     0,    93,     0,    92,    93,
     0,    94,     0,    85,     0,    72,     0,    52,     0,   108,
    52,     0,   113,    52,     0,   104,     0,    95,    52,     0,
   103,    52,     0,   123,    52,     0,   124,    52,     0,    28,
    52,     0,    29,    52,     0,    30,   114,     0,    30,     0,
    21,    57,   114,    58,    93,     0,    21,    57,   114,    58,
    93,    22,    93,     0,    98,     0,    99,     0,   100,     0,
   101,     0,    23,    57,   102,    52,   114,    52,   102,    58,
    93,     0,    23,    57,   102,    52,    52,   102,    58,    93,
     0,    25,    57,   114,    58,    93,     0,    26,    93,    27,
   114,    52,     0,    24,   110,    57,   114,    58,    93,     0,
    24,    57,   110,    73,   114,    58,    93,     0,     0,   108,
     0,   113,     0,   104,     0,    31,    57,    32,    58,     0,
    96,     0,    97,     0,   110,    57,   105,    58,     0,    73,
    57,   105,    58,     0,     0,   106,     0,   107,     0,   106,
    55,   107,     0,   114,     0,   110,    56,   114,     0,   109,
    33,   114,     0,   109,    37,   114,     0,   109,    38,   114,
     0,   109,    39,   114,     0,   109,    40,   114,     0,   109,
    41,   114,     0,   109,    34,   114,     0,   109,    35,   114,
     0,   109,    36,   114,     0,   110,     0,   111,     0,    68,
     0,   110,    59,   112,    60,     0,   114,     0,    48,   109,
     0,    49,   109,     0,   109,    48,     0,   109,    49,     0,
    14,   109,     0,    13,   109,     0,    57,   114,    58,     0,
   114,    50,   114,     0,    61,   114,     0,   114,    20,   114,
     0,   114,    13,   114,     0,   114,    14,   114,     0,    62,
   114,     0,   114,    16,   114,     0,   114,    17,   114,     0,
   114,    51,   114,     0,   114,    18,   114,     0,   114,    19,
   114,     0,   114,    45,   114,     0,   114,    46,   114,     0,
   114,    47,   114,     0,   113,     0,   114,    15,   114,     0,
   114,    12,   114,     0,   114,     5,   114,     0,   114,     4,
   114,     0,   114,     6,   114,     0,   114,     7,   114,     0,
   114,     8,   114,     0,   114,     9,   114,     0,   114,    65,
   114,     0,   114,    63,   114,     0,   114,    10,   114,     0,
   114,    11,   114,     0,   120,     0,   108,     0,   122,     0,
   118,     0,   115,     0,    86,     0,    59,   116,    60,     0,
   117,     0,   117,    55,   116,     0,   119,     0,    32,    64,
   119,     0,    32,     0,    66,     0,   118,     0,   121,     0,
   111,     0,   104,     0,   110,     0,    66,    69,    66,    69,
    66,    69,    66,     0,    70,    84,     0,    71,    84,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
    85,    86,    89,    91,    94,    96,    99,   103,   104,   107,
   109,   110,   111,   112,   113,   116,   118,   119,   122,   124,
   127,   128,   129,   132,   133,   134,   137,   139,   142,   144,
   147,   148,   149,   152,   154,   157,   159,   160,   163,   164,
   165,   166,   167,   168,   169,   170,   171,   172,   175,   177,
   180,   182,   185,   187,   188,   189,   192,   194,   197,   201,
   205,   207,   210,   211,   212,   213,   216,   220,   222,   223,
   224,   227,   228,   230,   232,   235,   237,   240,   242,   243,
   244,   245,   246,   247,   248,   249,   252,   254,   257,   261,
   265,   269,   271,   272,   273,   274,   275,   278,   279,   280,
   281,   282,   283,   284,   285,   286,   287,   288,   289,   290,
   291,   292,   293,   294,   295,   296,   297,   298,   299,   300,
   301,   302,   303,   304,   305,   306,   307,   308,   309,   310,
   311,   314,   318,   320,   323,   325,   330,   332,   336,   340,
   342,   343,   346,   350,   354,   358
};

static const char * const yytname[] = {   "$","error","$undefined.","FUNCTION",
"EQ","NE","LT","GT","LE","GE","SEARCH_SUBSTR","NOT_SEARCH_SUBSTR","POWER","ADD",
"SUB","MUL","DIV","MOD","XOR","OR","OR_OP","IF","ELSE","FOR","FOREACH","WHILE",
"REPEAT","UNTIL","BREAK","CONTINUE","RETURN","INCLUDE","STR_FIRST","ASSIGN",
"RIGHT_ASSIGN","RIGHT_RIGHT_ASSIGN","LEFT_ASSIGN","ADD_ASSIGN","SUB_ASSIGN",
"MUL_ASSIGN","DIV_ASSIGN","MOD_ASSIGN","AND_ASSIGN","XOR_ASSIGN","OR_ASSIGN",
"RIGHT_OP","RIGHT_OP_3","LEFT_OP","INC_OP","DEC_OP","AND_OP","AND","SEMICOLON",
"LEFT_BRACE","RIGHT_BRACE","COMMA","COLON","LEFT_PARENTHESIS","RIGHT_PARENTHESIS",
"LEFT_SQ_BRACKET","RIGHT_SQ_BRACKET","NOT","BIT","NOT_BIT","ARROW","ASSIGN_BIT",
"INTEGER","IF_1","IDENTIFIER","POINT","LOCAL","GLOBAL","COMMENT","IN_ITER","UPLUS",
"UMINUS","EXPORT","IMPORT","REFERENCE","start","command_declaration_list","command_declaration",
"function_declaration","argument_declaration","first_argument_declaration","body",
"body_arg","first_argument_list_bracket","first_argument_list_brace","argument_brace",
"argument_bracket","brace_ident","command_list","command","simple_command","ret",
"if_body","loop","for_loop","while_loop","repeat_loop","foreach_loop","aff_func",
"inc","function_call","argument_list","first_argument_list","argument","aff",
"lvalue","identifier","array_elem","array_index","post_pre_command","expression",
"const_array","list_array_data","array_data","atom","simple_array_data","var",
"var_name","ipaddr","loc","glob",""
};
#endif

static const short yyr1[] = {     0,
    79,    79,    80,    80,    81,    81,    82,    83,    83,    84,
    84,    84,    84,    84,    84,    85,    85,    85,    86,    86,
    87,    87,    87,    88,    88,    88,    89,    89,    90,    90,
    91,    91,    91,    92,    92,    93,    93,    93,    94,    94,
    94,    94,    94,    94,    94,    94,    94,    94,    95,    95,
    96,    96,    97,    97,    97,    97,    98,    98,    99,   100,
   101,   101,   102,   102,   102,   102,   103,   104,   104,   104,
   104,   105,   105,   106,   106,   107,   107,   108,   108,   108,
   108,   108,   108,   108,   108,   108,   109,   109,   110,   111,
   112,   113,   113,   113,   113,   113,   113,   114,   114,   114,
   114,   114,   114,   114,   114,   114,   114,   114,   114,   114,
   114,   114,   114,   114,   114,   114,   114,   114,   114,   114,
   114,   114,   114,   114,   114,   114,   114,   114,   114,   114,
   114,   115,   116,   116,   117,   117,   118,   118,   119,   120,
   120,   120,   121,   122,   123,   124
};

static const short yyr2[] = {     0,
     0,     1,     1,     2,     1,     1,     6,     0,     1,     1,
     3,     2,     4,     3,     5,     3,     2,     2,     3,     3,
     0,     1,     3,     0,     1,     3,     3,     3,     2,     1,
     1,     1,     1,     1,     2,     1,     1,     1,     1,     2,
     2,     1,     2,     2,     2,     2,     2,     2,     2,     1,
     5,     7,     1,     1,     1,     1,     9,     8,     5,     5,
     6,     7,     0,     1,     1,     1,     4,     1,     1,     4,
     4,     0,     1,     1,     3,     1,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     1,     1,     1,     4,
     1,     2,     2,     2,     2,     2,     2,     3,     3,     2,
     3,     3,     3,     2,     3,     3,     3,     3,     3,     3,
     3,     3,     1,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     1,     1,     1,     1,     1,
     1,     3,     1,     3,     1,     3,     1,     1,     1,     1,
     1,     1,     1,     7,     2,     2
};

static const short yydefact[] = {     1,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    50,     0,     0,     0,    39,     0,    89,     0,     0,    38,
     0,     2,     3,     6,    37,     5,    36,     0,    68,    69,
    53,    54,    55,    56,     0,    42,     0,     0,    87,    88,
     0,     0,     0,     0,    97,    87,    96,     0,    63,     0,
     0,     0,     0,    47,    48,   137,    24,     0,    21,     0,
     0,   138,   131,   142,   127,   143,   141,   113,    49,   130,
   129,   126,   140,   128,     0,    92,    93,    17,     0,    34,
     0,   145,     0,    10,   146,    72,     4,    18,    43,    44,
    40,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    94,    95,    72,     0,    41,    45,    46,     8,     0,     0,
    66,    64,    65,     0,     0,     0,     0,    32,    31,     0,
    25,     0,    33,     0,   137,     0,   138,     0,    22,    30,
     0,     0,   133,   139,   135,   100,   104,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,    16,    35,    12,     0,     0,     0,    73,
    74,   143,    76,    78,    84,    85,    86,    79,    80,    81,
    82,    83,     0,     0,    91,     0,     9,     0,     0,     0,
     0,     0,     0,    19,     0,     0,    98,     0,    29,     0,
    20,   132,     0,     0,   117,   116,   118,   119,   120,   121,
   124,   125,   115,   102,   103,   114,   105,   106,   108,   109,
   101,   110,   111,   112,    99,   107,   123,   122,    67,     0,
    14,    11,    71,     0,     0,    70,    90,     0,    51,    63,
     0,     0,     0,    59,    60,    26,    27,    28,    33,   136,
    23,   134,     0,    13,     0,    75,    77,     7,     0,    18,
     0,    63,     0,    61,     0,    15,    52,     0,     0,    62,
     0,    58,     0,   144,    57,     0,     0,     0
};

static const short yydefgoto[] = {   276,
    22,    23,    24,   186,    82,    25,    63,   128,   120,   121,
   129,   122,    79,    26,    27,    28,    29,    30,    31,    32,
    33,    34,   110,    35,    64,   169,   170,   171,    65,    38,
    66,    67,   184,    68,   173,    70,   132,   133,    71,   135,
    72,    73,    74,    42,    43
};

static const short yypact[] = {   456,
   -32,   -20,   -20,   -10,    -6,   -42,    -5,   972,     8,    11,
  1005,    17,   -20,   -20,-32768,   866,-32768,   -44,   -44,-32768,
    23,-32768,   456,-32768,-32768,    13,-32768,    21,-32768,-32768,
-32768,-32768,-32768,-32768,    30,-32768,    31,   358,    18,-32768,
    35,    39,    40,    37,-32768,    36,-32768,  1005,    16,   -20,
    41,  1005,     6,-32768,-32768,-32768,   -22,  1005,   390,  1005,
  1005,    27,-32768,-32768,-32768,   921,   974,-32768,   858,-32768,
-32768,-32768,-32768,-32768,    65,-32768,-32768,-32768,   919,    13,
   -20,-32768,    66,   -28,-32768,  1005,-32768,-32768,-32768,-32768,
-32768,  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,
-32768,-32768,  1005,  1005,-32768,-32768,-32768,   -44,   526,    48,
-32768,-32768,-32768,    32,  1005,   547,  1005,-32768,-32768,   -33,
-32768,    50,-32768,   609,    43,    44,-32768,   -17,-32768,-32768,
    55,    63,    58,-32768,-32768,   858,   858,    67,  1005,  1005,
  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,
  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,  1005,
  1005,  1005,    71,-32768,    13,    69,  1005,   -44,    76,    81,
-32768,   458,   858,   858,   858,   858,   858,   858,   858,   858,
   858,   858,    86,    85,   858,    89,-32768,   972,   114,  1005,
   630,   972,   692,-32768,   -22,   193,-32768,   -21,-32768,    96,
-32768,-32768,   -12,    80,   858,   858,   858,   858,   858,   858,
   858,   858,   858,   858,   858,   858,   858,   858,   858,   858,
   858,   858,   858,   858,   858,   858,   858,   858,-32768,   -44,
   713,-32768,-32768,  1005,  1005,-32768,-32768,   972,   129,    16,
   775,   796,   972,    13,-32768,-32768,-32768,-32768,    55,-32768,
-32768,-32768,    87,-32768,   -44,-32768,   858,   130,    13,   972,
    98,    16,   972,    13,    88,-32768,    13,   972,   100,    13,
    94,    13,   972,-32768,    13,   154,   159,-32768
};

static const short yypgoto[] = {-32768,
   142,-32768,-32768,-32768,   -18,   -68,-32768,-32768,-32768,   -16,
   -26,   -19,-32768,   102,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,  -228,-32768,     9,    75,-32768,   -51,    62,   112,
     0,    53,-32768,    93,   286,-32768,   -14,-32768,   -55,   -13,
-32768,-32768,-32768,-32768,-32768
};


#define	YYLAST		1078


static const short yytable[] = {    39,
    85,    46,    46,   134,   -87,    51,    81,    39,    36,   118,
    56,   261,    46,    46,    50,    39,    36,    84,    84,   125,
   194,   195,    39,    17,    36,    17,   168,    88,     2,     3,
   104,    36,   117,   269,    88,    44,     4,   200,     5,     6,
     7,     8,   201,   119,   127,    17,    48,    17,    39,   114,
    49,    52,    40,   127,    40,    40,   123,   111,   131,    54,
    40,    37,    55,    13,    14,    40,    40,   130,    40,    37,
    40,    40,    89,    75,   103,    40,   104,    37,    39,    86,
   166,    90,    91,    17,    37,   172,   105,    36,    21,   187,
   106,   107,    41,   108,   104,   138,   163,   115,   167,   189,
    41,    40,   172,   199,   190,   196,   198,    84,    41,    53,
   112,   103,   203,    45,    47,    41,     4,    80,     5,     6,
     7,     8,   202,   230,    76,    77,     2,     3,   229,    83,
    83,    40,   204,   233,     4,   234,     5,     6,     7,     8,
    37,   113,   134,   236,   237,    56,   238,   134,   253,   232,
   260,   -37,   265,   277,   126,   268,   271,   273,   278,   274,
    40,    13,    14,    17,    87,   240,    57,    84,    21,   258,
    58,    41,    59,   251,    60,    61,   247,   183,   246,    62,
   165,    17,   256,     0,   250,     0,    21,    39,   252,     0,
     0,    39,     0,     0,   123,   249,    36,     0,     0,   131,
    36,     0,     0,     0,   248,     0,     0,     0,   130,     0,
     0,   254,     0,     4,     0,     5,     6,     7,     8,    83,
    40,     0,     0,     0,   118,     0,     0,     0,     0,    84,
     0,     0,     0,   172,     0,     0,   266,    39,     0,    39,
    40,     0,    39,     0,    40,     0,    36,     0,   111,    37,
     0,    36,     0,    37,    84,     0,     0,     0,   119,    39,
    17,    39,    39,     0,     0,    21,     0,    39,    36,     0,
   111,    36,    39,     0,     0,     0,    36,     0,     0,    83,
    41,    36,    40,     0,    41,     0,     0,     0,     0,   239,
    40,     0,    40,   244,     0,    40,    69,     0,     0,    37,
     0,   112,     0,     0,    37,     0,     0,    40,     0,     0,
     0,     0,    40,     0,    40,    40,     0,     0,     0,     0,
    40,    37,     0,   112,    37,    40,     0,     0,     0,    37,
    41,     0,   113,   109,    37,    41,     0,   116,     0,   259,
     0,    83,     0,   124,   264,   136,   137,     0,     0,     0,
     0,     0,    41,     0,   113,    41,     0,     0,     0,     0,
    41,   267,     0,     0,   270,    41,    83,     0,     0,   272,
     0,     0,     0,     0,   275,     0,     0,   174,   175,   176,
   177,   178,   179,   180,   181,   182,     0,     0,     0,   185,
    92,    93,    94,    95,    96,    97,    98,    99,   100,     0,
   191,     0,   193,     0,     0,   101,   102,     0,     0,     0,
     4,     0,     5,     6,     7,     8,     0,     0,     0,     0,
     0,   125,     0,     0,   205,   206,   207,   208,   209,   210,
   211,   212,   213,   214,   215,   216,   217,   218,   219,   220,
   221,   222,   223,   224,   225,   226,   227,   228,   126,     0,
     0,     0,   231,     0,     0,   127,     0,    17,     1,     0,
     0,     0,    21,     0,     0,     0,     0,     0,     2,     3,
     0,     0,     0,     0,   241,   242,     4,     0,     5,     6,
     7,     8,     0,     9,    10,    11,    12,     0,     0,     0,
   -87,   -87,   -87,   -87,   -87,   -87,   -87,   -87,   -87,     0,
     0,     0,     0,    13,    14,   -87,   -87,    15,    16,     0,
     0,     0,     0,   235,   103,     0,   104,     0,     0,     0,
   257,     0,     0,    17,     0,    18,    19,    20,    21,   139,
   140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
   150,   151,   152,   153,   154,   155,     0,     0,     0,     0,
   139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
   149,   150,   151,   152,   153,   154,   155,     0,     0,     0,
   156,   157,   158,     0,     0,   159,   160,     0,     0,     0,
     0,     0,     0,   188,     0,     0,     0,     0,   161,     0,
   162,   156,   157,   158,     0,     0,   159,   160,     0,     0,
     0,     0,     0,     0,   192,     0,     0,     0,     0,   161,
     0,   162,   139,   140,   141,   142,   143,   144,   145,   146,
   147,   148,   149,   150,   151,   152,   153,   154,   155,     0,
     0,     0,     0,   139,   140,   141,   142,   143,   144,   145,
   146,   147,   148,   149,   150,   151,   152,   153,   154,   155,
     0,     0,     0,   156,   157,   158,     0,     0,   159,   160,
     0,     0,     0,     0,     0,     0,   197,     0,     0,     0,
     0,   161,     0,   162,   156,   157,   158,     0,     0,   159,
   160,     0,     0,     0,     0,     0,     0,   243,     0,     0,
     0,     0,   161,     0,   162,   139,   140,   141,   142,   143,
   144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
   154,   155,     0,     0,     0,     0,   139,   140,   141,   142,
   143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
   153,   154,   155,     0,     0,     0,   156,   157,   158,     0,
     0,   159,   160,   245,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,   161,     0,   162,   156,   157,   158,
     0,     0,   159,   160,     0,     0,     0,   255,     0,     0,
     0,     0,     0,     0,     0,   161,     0,   162,   139,   140,
   141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
   151,   152,   153,   154,   155,     0,     0,     0,     0,   139,
   140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
   150,   151,   152,   153,   154,   155,     0,     0,     0,   156,
   157,   158,     0,     0,   159,   160,   262,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,   161,     0,   162,
   156,   157,   158,     0,     0,   159,   160,     0,     0,     0,
     0,     0,     0,   263,     0,     0,     0,     0,   161,     0,
   162,   139,   140,   141,   142,   143,   144,   145,   146,   147,
   148,   149,   150,   151,   152,   153,   154,   155,     2,     3,
     0,     0,     0,     0,     0,     0,     4,     0,     5,     6,
     7,     8,     0,     9,    10,    11,    12,     0,     0,     0,
     0,     0,   156,   157,   158,     0,     0,   159,   160,     0,
     0,     0,     0,    13,    14,     0,     0,    15,    16,    78,
   161,     0,   162,     0,     0,     0,     0,     0,     0,     0,
     0,     2,     3,    17,     0,    18,    19,    20,    21,     4,
     0,     5,     6,     7,     8,     0,     9,    10,    11,    12,
     0,     0,     0,   -87,   -87,   -87,   -87,   -87,   -87,   -87,
   -87,   -87,     0,     0,     0,     0,    13,    14,   -87,   -87,
    15,    16,   164,     0,     0,     0,     0,   103,     0,   104,
     0,     0,     0,     0,     2,     3,    17,     0,    18,    19,
    20,    21,     4,     0,     5,     6,     7,     8,     0,     9,
    10,    11,    12,     0,     0,     0,   -88,   -88,   -88,   -88,
   -88,   -88,   -88,   -88,   -88,     0,     0,     2,     3,    13,
    14,   -88,   -88,    15,    16,     4,     0,     5,     6,     7,
     8,     0,     0,     0,     0,     0,    56,     0,     0,    17,
     0,    18,    19,    20,    21,     0,     0,     0,     0,     0,
     0,     0,    13,    14,     0,     0,     0,    57,     0,     0,
     0,    58,     0,    59,     0,    60,    61,     0,     0,     0,
    62,     0,    17,     0,     0,     0,     0,    21
};

static const short yycheck[] = {     0,
    19,     2,     3,    59,    33,     6,    51,     8,     0,    32,
    32,   240,    13,    14,    57,    16,     8,    18,    19,    32,
    54,    55,    23,    68,    16,    68,    55,    22,    13,    14,
    59,    23,    27,   262,    22,    68,    21,    55,    23,    24,
    25,    26,    60,    66,    66,    68,    57,    68,    49,    50,
    57,    57,     0,    66,     2,     3,    57,    49,    59,    52,
     8,     0,    52,    48,    49,    13,    14,    59,    16,     8,
    18,    19,    52,    57,    57,    23,    59,    16,    79,    57,
    81,    52,    52,    68,    23,    86,    52,    79,    73,   108,
    52,    52,     0,    57,    59,    69,    32,    57,    33,    52,
     8,    49,   103,    60,    73,    56,    64,   108,    16,     8,
    49,    57,    55,     2,     3,    23,    21,    16,    23,    24,
    25,    26,    60,    55,    13,    14,    13,    14,    58,    18,
    19,    79,    66,    58,    21,    55,    23,    24,    25,    26,
    79,    49,   198,    58,    60,    32,    58,   203,    69,   168,
    22,    22,    66,     0,    59,    58,    69,    58,     0,    66,
   108,    48,    49,    68,    23,    52,    53,   168,    73,   238,
    57,    79,    59,   200,    61,    62,   196,   103,   195,    66,
    79,    68,   234,    -1,   198,    -1,    73,   188,   203,    -1,
    -1,   192,    -1,    -1,   195,   196,   188,    -1,    -1,   200,
   192,    -1,    -1,    -1,   196,    -1,    -1,    -1,   200,    -1,
    -1,   230,    -1,    21,    -1,    23,    24,    25,    26,   108,
   168,    -1,    -1,    -1,    32,    -1,    -1,    -1,    -1,   230,
    -1,    -1,    -1,   234,    -1,    -1,   255,   238,    -1,   240,
   188,    -1,   243,    -1,   192,    -1,   238,    -1,   240,   188,
    -1,   243,    -1,   192,   255,    -1,    -1,    -1,    66,   260,
    68,   262,   263,    -1,    -1,    73,    -1,   268,   260,    -1,
   262,   263,   273,    -1,    -1,    -1,   268,    -1,    -1,   168,
   188,   273,   230,    -1,   192,    -1,    -1,    -1,    -1,   188,
   238,    -1,   240,   192,    -1,   243,    11,    -1,    -1,   238,
    -1,   240,    -1,    -1,   243,    -1,    -1,   255,    -1,    -1,
    -1,    -1,   260,    -1,   262,   263,    -1,    -1,    -1,    -1,
   268,   260,    -1,   262,   263,   273,    -1,    -1,    -1,   268,
   238,    -1,   240,    48,   273,   243,    -1,    52,    -1,   238,
    -1,   230,    -1,    58,   243,    60,    61,    -1,    -1,    -1,
    -1,    -1,   260,    -1,   262,   263,    -1,    -1,    -1,    -1,
   268,   260,    -1,    -1,   263,   273,   255,    -1,    -1,   268,
    -1,    -1,    -1,    -1,   273,    -1,    -1,    92,    93,    94,
    95,    96,    97,    98,    99,   100,    -1,    -1,    -1,   104,
    33,    34,    35,    36,    37,    38,    39,    40,    41,    -1,
   115,    -1,   117,    -1,    -1,    48,    49,    -1,    -1,    -1,
    21,    -1,    23,    24,    25,    26,    -1,    -1,    -1,    -1,
    -1,    32,    -1,    -1,   139,   140,   141,   142,   143,   144,
   145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
   155,   156,   157,   158,   159,   160,   161,   162,    59,    -1,
    -1,    -1,   167,    -1,    -1,    66,    -1,    68,     3,    -1,
    -1,    -1,    73,    -1,    -1,    -1,    -1,    -1,    13,    14,
    -1,    -1,    -1,    -1,   189,   190,    21,    -1,    23,    24,
    25,    26,    -1,    28,    29,    30,    31,    -1,    -1,    -1,
    33,    34,    35,    36,    37,    38,    39,    40,    41,    -1,
    -1,    -1,    -1,    48,    49,    48,    49,    52,    53,    -1,
    -1,    -1,    -1,    56,    57,    -1,    59,    -1,    -1,    -1,
   235,    -1,    -1,    68,    -1,    70,    71,    72,    73,     4,
     5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
    15,    16,    17,    18,    19,    20,    -1,    -1,    -1,    -1,
     4,     5,     6,     7,     8,     9,    10,    11,    12,    13,
    14,    15,    16,    17,    18,    19,    20,    -1,    -1,    -1,
    45,    46,    47,    -1,    -1,    50,    51,    -1,    -1,    -1,
    -1,    -1,    -1,    58,    -1,    -1,    -1,    -1,    63,    -1,
    65,    45,    46,    47,    -1,    -1,    50,    51,    -1,    -1,
    -1,    -1,    -1,    -1,    58,    -1,    -1,    -1,    -1,    63,
    -1,    65,     4,     5,     6,     7,     8,     9,    10,    11,
    12,    13,    14,    15,    16,    17,    18,    19,    20,    -1,
    -1,    -1,    -1,     4,     5,     6,     7,     8,     9,    10,
    11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
    -1,    -1,    -1,    45,    46,    47,    -1,    -1,    50,    51,
    -1,    -1,    -1,    -1,    -1,    -1,    58,    -1,    -1,    -1,
    -1,    63,    -1,    65,    45,    46,    47,    -1,    -1,    50,
    51,    -1,    -1,    -1,    -1,    -1,    -1,    58,    -1,    -1,
    -1,    -1,    63,    -1,    65,     4,     5,     6,     7,     8,
     9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
    19,    20,    -1,    -1,    -1,    -1,     4,     5,     6,     7,
     8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
    18,    19,    20,    -1,    -1,    -1,    45,    46,    47,    -1,
    -1,    50,    51,    52,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    63,    -1,    65,    45,    46,    47,
    -1,    -1,    50,    51,    -1,    -1,    -1,    55,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    63,    -1,    65,     4,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    20,    -1,    -1,    -1,    -1,     4,
     5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
    15,    16,    17,    18,    19,    20,    -1,    -1,    -1,    45,
    46,    47,    -1,    -1,    50,    51,    52,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,    63,    -1,    65,
    45,    46,    47,    -1,    -1,    50,    51,    -1,    -1,    -1,
    -1,    -1,    -1,    58,    -1,    -1,    -1,    -1,    63,    -1,
    65,     4,     5,     6,     7,     8,     9,    10,    11,    12,
    13,    14,    15,    16,    17,    18,    19,    20,    13,    14,
    -1,    -1,    -1,    -1,    -1,    -1,    21,    -1,    23,    24,
    25,    26,    -1,    28,    29,    30,    31,    -1,    -1,    -1,
    -1,    -1,    45,    46,    47,    -1,    -1,    50,    51,    -1,
    -1,    -1,    -1,    48,    49,    -1,    -1,    52,    53,    54,
    63,    -1,    65,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    13,    14,    68,    -1,    70,    71,    72,    73,    21,
    -1,    23,    24,    25,    26,    -1,    28,    29,    30,    31,
    -1,    -1,    -1,    33,    34,    35,    36,    37,    38,    39,
    40,    41,    -1,    -1,    -1,    -1,    48,    49,    48,    49,
    52,    53,    54,    -1,    -1,    -1,    -1,    57,    -1,    59,
    -1,    -1,    -1,    -1,    13,    14,    68,    -1,    70,    71,
    72,    73,    21,    -1,    23,    24,    25,    26,    -1,    28,
    29,    30,    31,    -1,    -1,    -1,    33,    34,    35,    36,
    37,    38,    39,    40,    41,    -1,    -1,    13,    14,    48,
    49,    48,    49,    52,    53,    21,    -1,    23,    24,    25,
    26,    -1,    -1,    -1,    -1,    -1,    32,    -1,    -1,    68,
    -1,    70,    71,    72,    73,    -1,    -1,    -1,    -1,    -1,
    -1,    -1,    48,    49,    -1,    -1,    -1,    53,    -1,    -1,
    -1,    57,    -1,    59,    -1,    61,    62,    -1,    -1,    -1,
    66,    -1,    68,    -1,    -1,    -1,    -1,    73
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
#line 363 "nasl_grammar.y"

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
