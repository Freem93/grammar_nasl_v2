#TRUSTED 75accfc31c41f4ca63ed3d951863b081bb7eb84b3480ac3bb558c60fce703a0bf5b2563677a49a6aca3529e6cd0c06ed4edfaec27e36a80128965705b9f5b78c68b7112e7977a84548ee409346c75476ab62fba312f2646f45e69cdedf0be780425cbc2a62a4657f0c3295b3485b5242f7022be092cf58fa41947d404b65e2cd9d802c4a8d7706fa31c0522811b806f4373396c005327cd595fabf829a4939892f55d576353bb33c80e041ee283e4058cf84c16df082c8d7cba7225d5319bb21eadbbd38a788dbc6528af0f6a1e42cc4a6e262250530c53c9c670ea879a17fb6d8daecf2439a300d008b0283e1316339f0cf3285ea457222e07bb4787b3cfd3d57fdf88bba236feae149f925bb5d543849638d34277d73ef1c052e3ded6ebe72db5334e0d4b2cb1f0fba4e53b4d0387060a53824ad85903181cdcf868e9063f3f18bc836e5a6da74f32dfe993d48ef4c9370ed63c43281938be8ff92ba155efbd9cfa2770f3b86daed48cd3e5cbeadd1cf50343e07a34e7dad103fd740022b06011bacf5f4eb992f57de06487d9ac0bc3aa80c1b6d829f372e5aa7b8ec4c9e5a22605a7d8b0cf2c872b842f6c34673da66c7e03184473dd124a57b7bd1dbf07403d2f2a7c11d20403076fe2fcaab337610095fae1e39c45d54e5fd5883aaacbc21343533bab7e34d431d6b7ec06c8496f0b63044a398f6ab31daaf447fb17e67
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# xcompat.inc
# Revision 1.4

#
# Backward compatibility functions
#
__desc_buf = NULL;



function cvss_vector_to_temporal_score(vector, base_score)
{
 local_var str;
 local_var Exploitability, RemediationLevel, ReportConfidence;
 local_var base;
 local_var score;
 
 str = vector;
 base_score = split(base_score, sep:'.');
 base = int(base_score[0]) * 1000 + int(base_score[1]) * 100;

 if ( "E:U/" >< str )
     Exploitability = 1176; # 0.85
 else if ( "E:POC/" >< str )
     Exploitability = 1111; # 0.9 
 else if ( "E:F/" >< str )
     Exploitability = 1052; # 0.95
 else if ( "E:H/" >< str )
     Exploitability = 1000; # 1.00
 else #if ( "E:/" >< str || "E:ND/" >< str )
     Exploitability = 1000; # 1.00

 if ( "/RL:OF/" >< str )
     RemediationLevel = 1149; # 0.87
 else if ( "/RL:TF/" >< str )
     RemediationLevel = 1111; # 0.90
 else if ( "/RL:W/" >< str )
     RemediationLevel = 1052; # 0.95
 else if ( "/RL:U/" >< str )
     RemediationLevel = 1000; # 1.00
 else #if ( "/RL:/" >< str || "/RL:ND/" >< str )
     RemediationLevel = 1000; # 1.00

 if ( "/RC:UC" >< str )
     ReportConfidence = 1111; # 0.90 
 else if ( "/RC:UR" >< str )
     ReportConfidence = 1052; # 0.95
 else if ( "/RC:C" >< str )
     ReportConfidence = 1000; # 1.00
 else #if ( "/RC:" >< str || "/RC:ND" >< str )
     ReportConfidence = 1000; # 1.00

 
 score = (base  * 1000)/Exploitability;
 score = (score * 1000)/RemediationLevel;
 score = (score * 1000)/ReportConfidence;
 if ( score % 100 >= 50) score += ( 100 - (score % 100) ); # Rounding
 if ( score / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( score % 100 >= 40) score += ( 100 - (score % 100) ); 
 }
 
 score = (score/10)*10;
 return strcat(score / 1000, ".", (score % 1000)/100);
}

function cvss_vector_to_base_score()
{
 local_var str;
 local_var c,i,a;
 local_var AccessVector, AccessComplexity, Authentication;
 local_var q,z;
 local_var cvss_score;

 str = _FCT_ANON_ARGS[0];
 if ( "AV:L/" >< str )
   AccessVector = 2532;
 else if ( "AV:A/" >< str )
   AccessVector = 1548;
 else if ( "AV:N/" >< str)
   AccessVector = 1000;
 else 
 {
   #display("Unknown CVSS access subvector (", str, ")!\n");
   return NULL;
 }

 if ( "AC:L/" >< str )
   AccessComplexity = 1408;
 else if ( "AC:M/" >< str )
   AccessComplexity = 1639;
 else if ( "AC:H/" >< str )
   AccessComplexity = 2857;
 else 
 {
   #display("Unknown CVSS access complexity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "Au:N/" >< str )
   Authentication = 1420;
 else if ( "Au:S/" >< str )
   Authentication = 1786;
 else if ( "Au:M/" >< str )
   Authentication = 2222;
 else 
 {
   #display("Unknown CVSS authentication subvector (", str, ")!\n");
   return NULL;
 }

 if ( "C:N/" >< str )
   c = 1000;
 else if ( "C:P/" >< str )
   c = 725;
 else if ( "C:C/" >< str )
   c = 340;
 else 
 {
   #display("Unknown CVSS confidentiality subvector (", str, ")!\n");
   return NULL;
 }

 if ( "I:N/" >< str )
   i = 1000;
 else if ( "I:P/" >< str )
   i = 725;
 else if ( "I:C/" >< str )
   i = 340;
 else 
 {
   #display("Unknown CVSS integrity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "/A:N" >< str )
   a = 1000;
 else if ( "/A:P" >< str )
   a = 725;
 else if ( "/A:C" >< str )
   a = 340;
 else 
 {
   #display("Unknown CVSS availability subvector (", str, ")!\n");
   return NULL;
 }

 if ( c + i + a == 3000 )
   return "0.0";

 z = (c*1000)/( (1000*1000)/i);
 z = (z*1000)/( (1000*1000)/a);
 z = 1000 - z;
 z = (1000*1000)/z;
 z = (10410*1000)/z;
 z = (z*1000)/1666;

 q = ( AccessComplexity  * 1000 ) / (( 1000 * 1000 )/Authentication );
 q = ( q * 1000 ) / ( ( 1000 * 1000 ) / AccessVector );
 q = ( 1000 * 1000 ) / q;
 q = q * 20000;
 q = q / 2500;

 z = ( z + q ) - 1500;
 z = (z * 11760)/10000;
 if ( z % 100 >= 50) z += ( 100 - (z % 100) ); # Rounding
 if ( z / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( z % 100 >= 40) z += ( 100 - (z % 100) ); 
 }
 
 z = (z/10)*10;
 cvss_score = strcat(z / 1000, ".", (z % 1000)/100);
 return cvss_score;
}



function xscript_set_attribute(attribute, value)
{
 local_var s, e;
 local_var i;

 if ( defined_func("script_set_attribute") )
 {
  script_set_attribute(attribute:attribute, value:value);
  return;
 }
 if ( isnull(attribute) || isnull(value) ) return;
 value = '' + value;
 e = strlen(value);
 for ( i = 0 ; value[i] >< ' \t\n\r' && i < e ; i ++ ) { };
 for ( e = strlen(value) - 1; value[e] >< ' \t\n\r' && e > 0 ; e -- ) { };
 value = substr(value, i, e);
 if ( strlen(__desc_buf[attribute]) ) __desc_buf[attribute] += '\n';
 __desc_buf[attribute] += value;
}

function xscript_set_cvss3_base_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  xscript_set_attribute(attribute:"cvss3_vector", value:vector);
}

function xscript_set_cvss3_temporal_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  xscript_set_attribute(attribute:"cvss3_temporal_vector", value:vector);
}

function xscript_set_cvss_base_vector()
{
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 xscript_set_attribute(attribute:"cvss_vector", value:vec);
 if ( nasl_level() < 4300 )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(vec);
}

function xscript_set_cvss_temporal_vector()
{
 local_var base_score;
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 xscript_set_attribute(attribute:"cvss_temporal_vector", value:vec);

 if ( nasl_level() < 4300 )
 {
  base_score = __desc_buf["cvss_base_score"];
  if ( ! isnull(base_score) )
   xscript_set_attribute(attribute:"cvss_temporal_score", value:cvss_vector_to_temporal_score(vector:vec, base_score:base_score));
 }
}

function xscript_end_attributes()
{
 local_var r;
 local_var buf;

 if ( defined_func("script_end_attributes") )
 {
  script_end_attributes();
  return;
 }

 if ( isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_vector"]) )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(__desc_buf["cvss_vector"]);


 if ( isnull(__desc_buf["risk_factor"]) )
 {
  if ( isnull(__desc_buf["cvss_base_score"]) )
	__desc_buf["risk_factor"] = "None";
  else {
   if ( int(__desc_buf["cvss_base_score"]) == 10 ) __desc_buf["risk_factor"] = "Critical";
   else if ( int(__desc_buf["cvss_base_score"]) >= 7 ) __desc_buf["risk_factor"] = "High";
   else if ( int(__desc_buf["cvss_base_score"]) >= 4 ) __desc_buf["risk_factor"] = "Medium";
   else if ( int(__desc_buf["cvss_base_score"]) > 0 ) __desc_buf["risk_factor"] = "Low";
   else __desc_buf["risk_factor"] = "None";
  }
 }



 buf = "";
 r = __desc_buf["synopsis"];
 if ( strlen(r) )
 {
   buf += 'Synopsis :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["description"];
 if ( strlen(r) )
 {
   buf += 'Description :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["see_also"];
 if ( strlen(r) )
 {
   buf += 'See also :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["solution"];
 if ( strlen(r) )
 {
   buf += 'Solution :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["risk_factor"];
 if ( strlen(r) )
 {
   buf += 'Risk factor :\n\n';
   buf += r;
   r = __desc_buf["cvss_base_score"];
   if ( r ) {
	buf += " / CVSS Base Score : " + r;
	r = __desc_buf["cvss_vector"];	
	if ( r ) buf += '\n(' + r + ')\n';
    	else buf += '\n';
    }
    else buf += '\n';
 }
 
 if ( nasl_level() < 3000 && strlen(buf) >= 3000 )
   buf = strcat(substr(buf, 0, 3000), "...");

 script_description(buf);
}

function xscript_osvdb_id()
{
  local_var	i;

  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"OSVDB", value: i);
}

function xscript_cwe_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"CWE", value: i);
}

function xscript_cvs_date()
{
  local_var	v;

  v = split(_FCT_ANON_ARGS[0], sep: ' ', keep: 0);
  if ( isnull(v) || isnull(v[1]) || v[1] !~ "^2[0-9]+/[0-9]+/[0-9]+$" ) return;
  xscript_set_attribute(attribute:"plugin_modification_date", value: v[1]);
}

# This lets the dependencies be .nasl when we're testing and .nbin
# when the code is running as .nbin on customer scanners.
# In other words, it lets us test everything without compiling anything to
# .nbin.
function script_dependencies_copy_extension()
{
  local_var extension, basename;
  if (SCRIPT_NAME =~ "\.nasl$")
    extension = ".nasl";
  else
    extension = ".nbin";

  foreach basename (_FCT_ANON_ARGS)
    script_dependencies(basename + extension);
}
