#TRUSTED 0b8a097b9e3cd5b20071f5172361134db429ad58c6f9423e72ba7a3d513353a2799cc488794ad396c26cbd92e3e0c4a92f90cfd72581b8ced33ff06a8ef81d1d1c0835717f43034e73e87c5ae1f9a95a8528f1815263589791e1d13b933c5cabcb8414b698ed2fc2f848637628608e9e79372116f5759f2356941dc5f6ec2bfe3d9ca44bf66d684ab0244187277a59637738c8f40479def768833c7cedf47d20a7ad292a09c8bc85dd1ec88f00fdc099b4db91bab5b916b63c394894f6f3caea71448770618eab0a82b497d25eb6751ec3b1cca0aad0a1d9101ad93108b9dff97569ac96b61cb7912b2058a6861d3ef55f027f040ff01d173aad9e82306753a4f265ec577da2cbc98e88b5281ef38fd1bca457ad159ca1a0517f6595d17fb93aa00fc1fe9a3a0f6f0e5507ebe45cc4c8a1d1be97440605844c3fd9b5fc442dcd1bd0972947dc72dbec9015c58526193e54b828af875a191889b3bfaf0e62cb1ec739918da064367e926007b060047798519a4081da6e1760f72c9b513691974142b1dc1e9fd31170ccba424da494bf049b52bb68f22c1f8ccaa19210e0a6f20df61cf92221da244797dee9e1e523d9908f86b4e6d7d0fd86f578bbf58c7dd109638c166cfd0aeb07c05e1049470eaa4b04f31891723e4ce277f41588b2a13b4358129a2c5920b4bb93a6817fa24463c9e5ae66caf0a9b97181d18e8850d59f1b
#
# (C) Tenable Network Security, Inc.
#
# Redistribution and use in source, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed by Tenable Network Security
#
# Revision 1.14

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



function script_set_attribute(attribute, value)
{
 local_var s, e;
 local_var i;

 if ( isnull(attribute) || isnull(value) ) return;
 value = '' + value;
 e = strlen(value);
 for ( i = 0 ; value[i] >< ' \t\n\r' && i < e ; i ++ ) { };
 for ( e = strlen(value) - 1; value[e] >< ' \t\n\r' && e > 0 ; e -- ) { };
 value = substr(value, i, e);
 if ( strlen(__desc_buf[attribute]) ) __desc_buf[attribute] += '\n';
 __desc_buf[attribute] += value;
}

function script_set_cvss3_base_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  script_set_attribute(attribute:"cvss3_vector", value:vector);
}

function script_set_cvss3_temporal_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  script_set_attribute(attribute:"cvss3_temporal_vector", value:vector);
}

function script_set_cvss_base_vector()
{
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 script_set_attribute(attribute:"cvss_vector", value:vec);
 if ( nasl_level() < 4300 )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(vec);
}

function script_set_cvss_temporal_vector()
{
 local_var base_score;
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 script_set_attribute(attribute:"cvss_temporal_vector", value:vec);

 if ( nasl_level() < 4300 )
 {
  base_score = __desc_buf["cvss_base_score"];
  if ( ! isnull(base_score) )
   script_set_attribute(attribute:"cvss_temporal_score", value:cvss_vector_to_temporal_score(vector:vec, base_score:base_score));
 }
}

function script_end_attributes()
{
 local_var r;
 local_var buf;


 if ( isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_vector"]) )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(__desc_buf["cvss_vector"]);

 if ( !isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_temporal_vector"] ) )
 {
  __desc_buf["cvss_temporal_score"] = cvss_vector_to_temporal_score(vector:__desc_buf["cvss_temporal_vector"], base_score:__desc_buf["cvss_base_score"]);
 }


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
	if ( __desc_buf["cvss_temporal_score"] ) 
	{
	 buf += 'CVSS Temporal Score : ' + __desc_buf["cvss_temporal_score"] + '\n' + '(' + __desc_buf["cvss_temporal_vector"] + ')\n';
	}
    }
    else buf += '\n';

    r = __desc_buf["exploit_available"];
    if ( strlen(r) ) buf += 'Public Exploit Available : ' + __desc_buf["exploit_available"] + '\n';
 }
 
 if ( nasl_level() < 3000 && strlen(buf) >= 3000 )
   buf = strcat(substr(buf, 0, 3000), "...");

 script_description(buf);
}


function script_osvdb_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"OSVDB", value: i);
}

function script_cwe_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"CWE", value: i);
}

function script_cvs_date()
{
  local_var	v;
  v = split(_FCT_ANON_ARGS[0], sep: ' ', keep: 0);
  if ( isnull(v) || isnull(v[1]) || v[1] !~ "^2[0-9]+/[0-9]+/[0-9]+$" ) return;
  script_set_attribute(attribute:"plugin_modification_date", value: v[1]);
}

