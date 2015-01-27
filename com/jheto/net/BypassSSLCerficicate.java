package com.jheto.net;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.AsyncTask;
import android.util.Log;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.json.JSONArray;
import org.json.JSONObject;

/*
 * https://github.com/JhetoX/BypassCertificateValidationForAndroid
 * 
 * This class provides connections to HTTPS service with invalid certificates and standard HTTP services, 
 * contains 3 common methods for service consumption, GET, POST and JSON.
 * 
 * Usage:
 * 
 * SendGET:
			
 * Hashtable<String,String> headers = new Hashtable<String,String>();
 * String url = "https://x.x.x.x/BypassSSLCerficicate/test.php";
 * headers.put("User-Agent", "BypassSSLCerficicate 1.1");
 * BypassSSLCerficicate bug = BypassSSLCerficicate.getInstance(true);
 * String content = bug.sendGET(url, headers);
			
 * SendPOST:
				
 * Hashtable<String,String> headers = new Hashtable<String,String>();
 * String url = "https://x.x.x.x/BypassSSLCerficicate/test.php";
 * headers.put("User-Agent", "BypassSSLCerficicate 1.1");
 * Hashtable<String,String> params = new Hashtable<String,String>();
 * params.put("name", "you");
 * BypassSSLCerficicate bug = BypassSSLCerficicate.getInstance(true);
 * String content = bug.sendPOST(url, headers, params);
			
 * SendJSON:
			
 * Hashtable<String,String> headers = new Hashtable<String,String>();
 * String url = "https://x.x.x.x/BypassSSLCerficicate/test.php";
 * headers.put("User-Agent", "BypassSSLCerficicate 1.1");
 * String json = "{\"key\":\"value\"}";
 * BypassSSLCerficicate bug = BypassSSLCerficicate.getInstance(true);
 * String content = bug.sendJSON(url, headers, json);
 * 
 * */
public class BypassSSLCerficicate {
	
	private static Vector<Hashtable<String, Object>> tableAnalysis = new Vector<Hashtable<String, Object>>();

	private static boolean USES_TRAFFIC_ANALYSIS = false;
	
	public static void resetTraficAnalysis(){
		tableAnalysis = new Vector<Hashtable<String, Object>>();
	}
	
	public static void enableTraficAnalysis(boolean enable){
		USES_TRAFFIC_ANALYSIS = enable;
	}
	
	public static boolean isEnableTraficAnalysis(){
		return USES_TRAFFIC_ANALYSIS;
	}
	
	private static void appendTraficAnalysis(String url, int download, int upload, int responseCode, String responseMessage){
		if(USES_TRAFFIC_ANALYSIS && tableAnalysis != null && url != null){
			Hashtable<String, Object> item = new Hashtable<String, Object>();
			item.put("http_msg", responseMessage);
			item.put("http_code", responseCode);
			item.put("download", download);
			item.put("upload", upload);
			item.put("url", url);
			tableAnalysis.add(item);
		}
	}
	
	public static String generateTraficAnalysis(){
		String inform = "";
		if(tableAnalysis != null && tableAnalysis.size()>0){
			for(int i=0; i<tableAnalysis.size(); i++){
				Hashtable<String, Object> item = tableAnalysis.get(i);
				inform += "Url: " + item.get("url").toString() + "\n";
				inform += "Upload: " + item.get("upload").toString() + " bytes \n";
				inform += "Download: " + item.get("download").toString() + " bytes \n\n";
				inform += "HTTP_CODE: " + item.get("http_code").toString() + " \n\n";
				inform += "HTTP_MESSAGE: " + item.get("http_msg").toString() + " \n\n";
			}
		}
		return inform;
	}
	
	private static CookieManager cookieManager = new CookieManager();
	
	/*
	 * This method enables cookie support.
	 * */
	public static void registerCookieManager(){
		try{
			CookieHandler.setDefault(cookieManager);
		}catch(Exception e){}
	}
	
	/*
	 * This method disables cookie support.
	 * */
	public static void unregisterCookieManager(){
		try{
			CookieHandler.setDefault(null);
		}catch(Exception e){}
	}
	
	/*
	 * This method cleans cookie manager.
	 * */
	public static void cleanCookieManager(){
		try{
			cookieManager = new CookieManager();
			CookieHandler.setDefault(cookieManager);
		}catch(Exception e){}
	}
	
	/*
	 * This method set a BasicAuthentication.
	 * 
	 * Params: 
	 * User: username  
	 * Pass: password
	 * */
	public static void setBasicAuthentication(final String user, final String pass){
		boolean containsAuthentication = (user != null && user.length()>0 && pass != null && pass.length()>0)? true:false;
		try{
			if(containsAuthentication){
				Authenticator.setDefault(new Authenticator() {
				     protected PasswordAuthentication getPasswordAuthentication() {
				    	 return new PasswordAuthentication(user, pass.toCharArray());
				     }
				});
			}
			else removeBasicAuthentication();
		}catch(Exception e){}
	}
	
	/*
	 * This method removes a Basic Authentication
	 * */
	public static void removeBasicAuthentication(){
		try{
			Authenticator.setDefault(null);
		}catch(Exception e){}
	}
	
	/*
	 * This method return a http response message.
	 * */
	public String getResponseMessage(){
		return responseMessage;
	} 
	
	/*
	 * This method return a http response code.
	 * */
	public int getResponseCode(){
		return responseCode;
	}
	
	/*
	 * This method returns a default headers
	 * */
	public static Hashtable<String,String> getDefaultHeaders(){
		Hashtable<String,String> headers = new Hashtable<String,String>();
		headers.put("User-Agent", "BypassSSLCerficicate 1.0");
		headers.put("Accept-Encoding", "gzip, deflate");
		headers.put("Accept", "*/*");
		return headers;
	}
	
	private boolean enableAllCertificates = false;
	private String responseMessage = null;
	private int responseCode = 0;
	
	private BypassSSLCerficicate(){
	}

	/*
	 * Create an instance of the class
	 * 
	 * Params:
	 * enableAllCertificates: true for https connections with active bypass invalid certificates
	 * */
	public static BypassSSLCerficicate getInstance(boolean enableAllCertificates){
		BypassSSLCerficicate cls = new BypassSSLCerficicate();
		cls.enableAllCertificates = enableAllCertificates;
		return cls;
	}

	@SuppressLint("TrulyRandom")
	private void enableAllCertificates(){
		try{
			X509TrustManager trustManager = new X509TrustManager() {
				@Override
				public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}
				@Override
				public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			};
			TrustManager[] trustAllCerts = new TrustManager[] {trustManager};

			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

			HostnameVerifier allHostsValid = new HostnameVerifier() {
				@Override
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			};
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

		}catch(Exception e){
			e.printStackTrace();
		}
	}

	private HttpURLConnection getURLConnection(String urlStr, boolean isGET) throws MalformedURLException, IOException {
		if(enableAllCertificates) enableAllCertificates();
		URL url = new URL(urlStr);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setInstanceFollowRedirects(true);
		conn.setConnectTimeout(1000 * 60);
		conn.setReadTimeout(1000 * 60);
		conn.setUseCaches(false);
		conn.setDoInput(true);
		if(isGET) conn.setRequestMethod("GET");
		else {
			conn.setDoOutput(true);
			conn.setRequestMethod("POST");
		}
		return conn;
	}

	private HttpURLConnection addHeaders(HttpURLConnection conn, Hashtable<String,String> params){
		if(conn != null && params != null && params.size()>0){
			try{
				Enumeration<String> keys = params.keys();
				while(keys.hasMoreElements()){
					String key = keys.nextElement();
					String value = params.get(key);
					if(key != null && value != null) conn.setRequestProperty(key, value);
				}
			}catch(Exception e){
				Log.e("Exception", e.toString());
			}
		}
		return conn;
	}

	private String addPostVars(HttpURLConnection conn, Hashtable<String,String> params){
		String urlParameters = "";
		try{
			String method = conn.getRequestMethod();
			if(method.equals("POST")){
				Enumeration<String> keys = params.keys();
				while(keys.hasMoreElements()){
					String key = URLEncoder.encode(keys.nextElement(), "UTF-8");
					String value = URLEncoder.encode(params.get(key), "UTF-8");
					if(key != null && value != null) {
						if(urlParameters.length() == 0) urlParameters += key + "=" + value;
						else urlParameters += "&" + key + "=" + value;
					}
				}
				if(urlParameters.length() > 0){
					DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
					wr.writeBytes(urlParameters);
					wr.flush();
					wr.close();
				}
			}
		}catch(Exception e){}
		return urlParameters;
	}

	private void addPostJson(HttpURLConnection conn, String json, boolean useUrlEncode){
		try{
			String method = conn.getRequestMethod();
			if(method.equals("POST")){
				DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
				if(useUrlEncode) wr.writeBytes(URLEncoder.encode(json,"UTF-8"));
				else wr.writeBytes(json);
				wr.flush();
				wr.close();
			}
		}catch(Exception e){}
	}

	private String getTextContent(HttpURLConnection conn) throws MalformedURLException, IOException {
		StringBuilder content = new StringBuilder();
		responseMessage = conn.getResponseMessage();
		responseCode = conn.getResponseCode();
		if(responseCode == 200){
			InputStream is = conn.getInputStream();
			byte[] bytes = new byte[1024];
			int numRead = 0;
			while ((numRead = is.read(bytes)) >= 0) {
				content.append(new String(bytes, 0, numRead));
			}
		}
		return content.toString();
	}

	/*
	 * This method lets you create a url with parameters such GET
	 * 
	 * Params: 
	 * Ulr: url of service
	 * Params: headers with the request will be made
	 * */
	public static String encodeUrl(String url, Hashtable<String,String> params){
		String outUrl = url;
		try{
			String urlParameters = "";
			Enumeration<String> keys = params.keys();
			while(keys.hasMoreElements()){
				String key = URLEncoder.encode(keys.nextElement(), "UTF-8");
				String value = URLEncoder.encode(params.get(key), "UTF-8");
				if(key != null && value != null) {
					if(urlParameters.length() == 0) urlParameters += "?" + key + "=" + value;
					else urlParameters += "&" + key + "=" + value;
				}
			}
			if(outUrl != null && urlParameters.length() > 0) outUrl += urlParameters;
		}catch(Exception e){}
		return outUrl;
	}
	
	private final static String CRLF = "\r\n";
	private final static String TWO_HYPHENS = "--";
	private final static String BOUNDARY =  "*****";
	
	public static String getMimeType(String filename){
		String mime = "application/octet-stream";
		try{
			String ext = filename.substring(filename.lastIndexOf(".")).toLowerCase();
			if(ext.equals(".3dm")) mime = "x-world/x-3dmf";
			else if(ext.equals(".3dmf")) mime = "x-world/x-3dmf";
			else if(ext.equals(".a")) mime = "application/octet-stream";
			else if(ext.equals(".aab")) mime = "application/x-authorware-bin";
			else if(ext.equals(".aam")) mime = "application/x-authorware-map";
			else if(ext.equals(".aas")) mime = "application/x-authorware-seg";
			else if(ext.equals(".abc")) mime = "text/vnd.abc";
			else if(ext.equals(".acgi")) mime = "text/html";
			else if(ext.equals(".afl")) mime = "video/animaflex";
			else if(ext.equals(".ai")) mime = "application/postscript";
			else if(ext.equals(".aif")) mime = "audio/aiff";
			else if(ext.equals(".aif")) mime = "audio/x-aiff";
			else if(ext.equals(".aifc")) mime = "audio/aiff";
			else if(ext.equals(".aifc")) mime = "audio/x-aiff";
			else if(ext.equals(".aiff")) mime = "audio/aiff";
			else if(ext.equals(".aiff")) mime = "audio/x-aiff";
			else if(ext.equals(".aim")) mime = "application/x-aim";
			else if(ext.equals(".aip")) mime = "text/x-audiosoft-intra";
			else if(ext.equals(".ani")) mime = "application/x-navi-animation";
			else if(ext.equals(".aos")) mime = "application/x-nokia-9000-communicator-add-on-software";
			else if(ext.equals(".aps")) mime = "application/mime";
			else if(ext.equals(".arc")) mime = "application/octet-stream";
			else if(ext.equals(".arj")) mime = "application/arj";
			else if(ext.equals(".arj")) mime = "application/octet-stream";
			else if(ext.equals(".art")) mime = "image/x-jg";
			else if(ext.equals(".asf")) mime = "video/x-ms-asf";
			else if(ext.equals(".asm")) mime = "text/x-asm";
			else if(ext.equals(".asp")) mime = "text/asp";
			else if(ext.equals(".asx")) mime = "application/x-mplayer2";
			else if(ext.equals(".asx")) mime = "video/x-ms-asf";
			else if(ext.equals(".asx")) mime = "video/x-ms-asf-plugin";
			else if(ext.equals(".au")) mime = "audio/basic";
			else if(ext.equals(".au")) mime = "audio/x-au";
			else if(ext.equals(".avi")) mime = "application/x-troff-msvideo";
			else if(ext.equals(".avi")) mime = "video/avi";
			else if(ext.equals(".avi")) mime = "video/msvideo";
			else if(ext.equals(".avi")) mime = "video/x-msvideo";
			else if(ext.equals(".avs")) mime = "video/avs-video";
			else if(ext.equals(".bcpio")) mime = "application/x-bcpio";
			else if(ext.equals(".bin")) mime = "application/mac-binary";
			else if(ext.equals(".bin")) mime = "application/macbinary";
			else if(ext.equals(".bin")) mime = "application/octet-stream";
			else if(ext.equals(".bin")) mime = "application/x-binary";
			else if(ext.equals(".bin")) mime = "application/x-macbinary";
			else if(ext.equals(".bm")) mime = "image/bmp";
			else if(ext.equals(".bmp")) mime = "image/bmp";
			else if(ext.equals(".bmp")) mime = "image/x-windows-bmp";
			else if(ext.equals(".boo")) mime = "application/book";
			else if(ext.equals(".book")) mime = "application/book";
			else if(ext.equals(".boz")) mime = "application/x-bzip2";
			else if(ext.equals(".bsh")) mime = "application/x-bsh";
			else if(ext.equals(".bz")) mime = "application/x-bzip";
			else if(ext.equals(".bz2")) mime = "application/x-bzip2";
			else if(ext.equals(".c")) mime = "text/plain";
			else if(ext.equals(".c")) mime = "text/x-c";
			else if(ext.equals(".c++")) mime = "text/plain";
			else if(ext.equals(".cat")) mime = "application/vnd.ms-pki.seccat";
			else if(ext.equals(".cc")) mime = "text/plain";
			else if(ext.equals(".cc")) mime = "text/x-c";
			else if(ext.equals(".ccad")) mime = "application/clariscad";
			else if(ext.equals(".cco")) mime = "application/x-cocoa";
			else if(ext.equals(".cdf")) mime = "application/cdf";
			else if(ext.equals(".cdf")) mime = "application/x-cdf";
			else if(ext.equals(".cdf")) mime = "application/x-netcdf";
			else if(ext.equals(".cer")) mime = "application/pkix-cert";
			else if(ext.equals(".cer")) mime = "application/x-x509-ca-cert";
			else if(ext.equals(".cha")) mime = "application/x-chat";
			else if(ext.equals(".chat")) mime = "application/x-chat";
			else if(ext.equals(".class")) mime = "application/java";
			else if(ext.equals(".class")) mime = "application/java-byte-code";
			else if(ext.equals(".class")) mime = "application/x-java-class";
			else if(ext.equals(".com")) mime = "application/octet-stream";
			else if(ext.equals(".com")) mime = "text/plain";
			else if(ext.equals(".conf")) mime = "text/plain";
			else if(ext.equals(".cpio")) mime = "application/x-cpio";
			else if(ext.equals(".cpp")) mime = "text/x-c";
			else if(ext.equals(".cpt")) mime = "application/mac-compactpro";
			else if(ext.equals(".cpt")) mime = "application/x-compactpro";
			else if(ext.equals(".cpt")) mime = "application/x-cpt";
			else if(ext.equals(".crl")) mime = "application/pkcs-crl";
			else if(ext.equals(".crl")) mime = "application/pkix-crl";
			else if(ext.equals(".crt")) mime = "application/pkix-cert";
			else if(ext.equals(".crt")) mime = "application/x-x509-ca-cert";
			else if(ext.equals(".crt")) mime = "application/x-x509-user-cert";
			else if(ext.equals(".csh")) mime = "application/x-csh";
			else if(ext.equals(".csh")) mime = "text/x-script.csh";
			else if(ext.equals(".css")) mime = "application/x-pointplus";
			else if(ext.equals(".css")) mime = "text/css";
			else if(ext.equals(".cxx")) mime = "text/plain";
			else if(ext.equals(".dcr")) mime = "application/x-director";
			else if(ext.equals(".deepv")) mime = "application/x-deepv";
			else if(ext.equals(".def")) mime = "text/plain";
			else if(ext.equals(".der")) mime = "application/x-x509-ca-cert";
			else if(ext.equals(".dif")) mime = "video/x-dv";
			else if(ext.equals(".dir")) mime = "application/x-director";
			else if(ext.equals(".dl")) mime = "video/dl";
			else if(ext.equals(".dl")) mime = "video/x-dl";
			else if(ext.equals(".doc")) mime = "application/msword";
			else if(ext.equals(".dot")) mime = "application/msword";
			else if(ext.equals(".dp")) mime = "application/commonground";
			else if(ext.equals(".drw")) mime = "application/drafting";
			else if(ext.equals(".dump")) mime = "application/octet-stream";
			else if(ext.equals(".dv")) mime = "video/x-dv";
			else if(ext.equals(".dvi")) mime = "application/x-dvi";
			else if(ext.equals(".dwf")) mime = "drawing/x-dwf (old)";
			else if(ext.equals(".dwf")) mime = "model/vnd.dwf";
			else if(ext.equals(".dwg")) mime = "application/acad";
			else if(ext.equals(".dwg")) mime = "image/vnd.dwg";
			else if(ext.equals(".dwg")) mime = "image/x-dwg";
			else if(ext.equals(".dxf")) mime = "application/dxf";
			else if(ext.equals(".dxf")) mime = "image/vnd.dwg";
			else if(ext.equals(".dxf")) mime = "image/x-dwg";
			else if(ext.equals(".dxr")) mime = "application/x-director";
			else if(ext.equals(".el")) mime = "text/x-script.elisp";
			else if(ext.equals(".elc")) mime = "application/x-bytecode.elisp (compiled elisp)";
			else if(ext.equals(".elc")) mime = "application/x-elc";
			else if(ext.equals(".env")) mime = "application/x-envoy";
			else if(ext.equals(".eps")) mime = "application/postscript";
			else if(ext.equals(".es")) mime = "application/x-esrehber";
			else if(ext.equals(".etx")) mime = "text/x-setext";
			else if(ext.equals(".evy")) mime = "application/envoy";
			else if(ext.equals(".evy")) mime = "application/x-envoy";
			else if(ext.equals(".exe")) mime = "application/octet-stream";
			else if(ext.equals(".f")) mime = "text/plain";
			else if(ext.equals(".f")) mime = "text/x-fortran";
			else if(ext.equals(".f77")) mime = "text/x-fortran";
			else if(ext.equals(".f90")) mime = "text/plain";
			else if(ext.equals(".f90")) mime = "text/x-fortran";
			else if(ext.equals(".fdf")) mime = "application/vnd.fdf";
			else if(ext.equals(".fif")) mime = "application/fractals";
			else if(ext.equals(".fif")) mime = "image/fif";
			else if(ext.equals(".fli")) mime = "video/fli";
			else if(ext.equals(".fli")) mime = "video/x-fli";
			else if(ext.equals(".flo")) mime = "image/florian";
			else if(ext.equals(".flx")) mime = "text/vnd.fmi.flexstor";
			else if(ext.equals(".fmf")) mime = "video/x-atomic3d-feature";
			else if(ext.equals(".for")) mime = "text/plain";
			else if(ext.equals(".for")) mime = "text/x-fortran";
			else if(ext.equals(".fpx")) mime = "image/vnd.fpx";
			else if(ext.equals(".fpx")) mime = "image/vnd.net-fpx";
			else if(ext.equals(".frl")) mime = "application/freeloader";
			else if(ext.equals(".funk")) mime = "audio/make";
			else if(ext.equals(".g")) mime = "text/plain";
			else if(ext.equals(".g3")) mime = "image/g3fax";
			else if(ext.equals(".gif")) mime = "image/gif";
			else if(ext.equals(".gl")) mime = "video/gl";
			else if(ext.equals(".gl")) mime = "video/x-gl";
			else if(ext.equals(".gsd")) mime = "audio/x-gsm";
			else if(ext.equals(".gsm")) mime = "audio/x-gsm";
			else if(ext.equals(".gsp")) mime = "application/x-gsp";
			else if(ext.equals(".gss")) mime = "application/x-gss";
			else if(ext.equals(".gtar")) mime = "application/x-gtar";
			else if(ext.equals(".gz")) mime = "application/x-compressed";
			else if(ext.equals(".gz")) mime = "application/x-gzip";
			else if(ext.equals(".gzip")) mime = "application/x-gzip";
			else if(ext.equals(".gzip")) mime = "multipart/x-gzip";
			else if(ext.equals(".h")) mime = "text/plain";
			else if(ext.equals(".h")) mime = "text/x-h";
			else if(ext.equals(".hdf")) mime = "application/x-hdf";
			else if(ext.equals(".help")) mime = "application/x-helpfile";
			else if(ext.equals(".hgl")) mime = "application/vnd.hp-hpgl";
			else if(ext.equals(".hh")) mime = "text/plain";
			else if(ext.equals(".hh")) mime = "text/x-h";
			else if(ext.equals(".hlb")) mime = "text/x-script";
			else if(ext.equals(".hlp")) mime = "application/hlp";
			else if(ext.equals(".hlp")) mime = "application/x-helpfile";
			else if(ext.equals(".hlp")) mime = "application/x-winhelp";
			else if(ext.equals(".hpg")) mime = "application/vnd.hp-hpgl";
			else if(ext.equals(".hpgl")) mime = "application/vnd.hp-hpgl";
			else if(ext.equals(".hqx")) mime = "application/binhex";
			else if(ext.equals(".hqx")) mime = "application/binhex4";
			else if(ext.equals(".hqx")) mime = "application/mac-binhex";
			else if(ext.equals(".hqx")) mime = "application/mac-binhex40";
			else if(ext.equals(".hqx")) mime = "application/x-binhex40";
			else if(ext.equals(".hqx")) mime = "application/x-mac-binhex40";
			else if(ext.equals(".hta")) mime = "application/hta";
			else if(ext.equals(".htc")) mime = "text/x-component";
			else if(ext.equals(".htm")) mime = "text/html";
			else if(ext.equals(".html")) mime = "text/html";
			else if(ext.equals(".htmls")) mime = "text/html";
			else if(ext.equals(".htt")) mime = "text/webviewhtml";
			else if(ext.equals(".htx")) mime = "text/html";
			else if(ext.equals(".ice")) mime = "x-conference/x-cooltalk";
			else if(ext.equals(".ico")) mime = "image/x-icon";
			else if(ext.equals(".idc")) mime = "text/plain";
			else if(ext.equals(".ief")) mime = "image/ief";
			else if(ext.equals(".iefs")) mime = "image/ief";
			else if(ext.equals(".iges")) mime = "application/iges";
			else if(ext.equals(".iges")) mime = "model/iges";
			else if(ext.equals(".igs")) mime = "application/iges";
			else if(ext.equals(".igs")) mime = "model/iges";
			else if(ext.equals(".ima")) mime = "application/x-ima";
			else if(ext.equals(".imap")) mime = "application/x-httpd-imap";
			else if(ext.equals(".inf")) mime = "application/inf";
			else if(ext.equals(".ins")) mime = "application/x-internett-signup";
			else if(ext.equals(".ip")) mime = "application/x-ip2";
			else if(ext.equals(".isu")) mime = "video/x-isvideo";
			else if(ext.equals(".it")) mime = "audio/it";
			else if(ext.equals(".iv")) mime = "application/x-inventor";
			else if(ext.equals(".ivr")) mime = "i-world/i-vrml";
			else if(ext.equals(".ivy")) mime = "application/x-livescreen";
			else if(ext.equals(".jam")) mime = "audio/x-jam";
			else if(ext.equals(".jav")) mime = "text/plain";
			else if(ext.equals(".jav")) mime = "text/x-java-source";
			else if(ext.equals(".java")) mime = "text/plain";
			else if(ext.equals(".java")) mime = "text/x-java-source";
			else if(ext.equals(".jcm")) mime = "application/x-java-commerce";
			else if(ext.equals(".jfif")) mime = "image/jpeg";
			else if(ext.equals(".jfif")) mime = "image/pjpeg";
			else if(ext.equals(".jfif-tbnl")) mime = "image/jpeg";
			else if(ext.equals(".jpe")) mime = "image/jpeg";
			else if(ext.equals(".jpe")) mime = "image/pjpeg";
			else if(ext.equals(".jpeg")) mime = "image/jpeg";
			else if(ext.equals(".jpeg")) mime = "image/pjpeg";
			else if(ext.equals(".jpg")) mime = "image/jpeg";
			else if(ext.equals(".jpg")) mime = "image/pjpeg";
			else if(ext.equals(".jps")) mime = "image/x-jps";
			else if(ext.equals(".js")) mime = "application/x-javascript";
			else if(ext.equals(".js")) mime = "application/javascript";
			else if(ext.equals(".js")) mime = "application/ecmascript";
			else if(ext.equals(".js")) mime = "text/javascript";
			else if(ext.equals(".js")) mime = "text/ecmascript";
			else if(ext.equals(".jut")) mime = "image/jutvision";
			else if(ext.equals(".kar")) mime = "audio/midi";
			else if(ext.equals(".kar")) mime = "music/x-karaoke";
			else if(ext.equals(".ksh")) mime = "application/x-ksh";
			else if(ext.equals(".ksh")) mime = "text/x-script.ksh";
			else if(ext.equals(".la")) mime = "audio/nspaudio";
			else if(ext.equals(".la")) mime = "audio/x-nspaudio";
			else if(ext.equals(".lam")) mime = "audio/x-liveaudio";
			else if(ext.equals(".latex")) mime = "application/x-latex";
			else if(ext.equals(".lha")) mime = "application/lha";
			else if(ext.equals(".lha")) mime = "application/octet-stream";
			else if(ext.equals(".lha")) mime = "application/x-lha";
			else if(ext.equals(".lhx")) mime = "application/octet-stream";
			else if(ext.equals(".list")) mime = "text/plain";
			else if(ext.equals(".lma")) mime = "audio/nspaudio";
			else if(ext.equals(".lma")) mime = "audio/x-nspaudio";
			else if(ext.equals(".log")) mime = "text/plain";
			else if(ext.equals(".lsp")) mime = "application/x-lisp";
			else if(ext.equals(".lsp")) mime = "text/x-script.lisp";
			else if(ext.equals(".lst")) mime = "text/plain";
			else if(ext.equals(".lsx")) mime = "text/x-la-asf";
			else if(ext.equals(".ltx")) mime = "application/x-latex";
			else if(ext.equals(".lzh")) mime = "application/octet-stream";
			else if(ext.equals(".lzh")) mime = "application/x-lzh";
			else if(ext.equals(".lzx")) mime = "application/lzx";
			else if(ext.equals(".lzx")) mime = "application/octet-stream";
			else if(ext.equals(".lzx")) mime = "application/x-lzx";
			else if(ext.equals(".m")) mime = "text/plain";
			else if(ext.equals(".m")) mime = "text/x-m";
			else if(ext.equals(".m1v")) mime = "video/mpeg";
			else if(ext.equals(".m2a")) mime = "audio/mpeg";
			else if(ext.equals(".m2v")) mime = "video/mpeg";
			else if(ext.equals(".m3u")) mime = "audio/x-mpequrl";
			else if(ext.equals(".man")) mime = "application/x-troff-man";
			else if(ext.equals(".map")) mime = "application/x-navimap";
			else if(ext.equals(".mar")) mime = "text/plain";
			else if(ext.equals(".mbd")) mime = "application/mbedlet";
			else if(ext.equals(".mc$")) mime = "application/x-magic-cap-package-1.0";
			else if(ext.equals(".mcd")) mime = "application/mcad";
			else if(ext.equals(".mcd")) mime = "application/x-mathcad";
			else if(ext.equals(".mcf")) mime = "image/vasa";
			else if(ext.equals(".mcf")) mime = "text/mcf";
			else if(ext.equals(".mcp")) mime = "application/netmc";
			else if(ext.equals(".me")) mime = "application/x-troff-me";
			else if(ext.equals(".mht")) mime = "message/rfc822";
			else if(ext.equals(".mhtml")) mime = "message/rfc822";
			else if(ext.equals(".mid")) mime = "application/x-midi";
			else if(ext.equals(".mid")) mime = "audio/midi";
			else if(ext.equals(".mid")) mime = "audio/x-mid";
			else if(ext.equals(".mid")) mime = "audio/x-midi";
			else if(ext.equals(".mid")) mime = "music/crescendo";
			else if(ext.equals(".mid")) mime = "x-music/x-midi";
			else if(ext.equals(".midi")) mime = "application/x-midi";
			else if(ext.equals(".midi")) mime = "audio/midi";
			else if(ext.equals(".midi")) mime = "audio/x-mid";
			else if(ext.equals(".midi")) mime = "audio/x-midi";
			else if(ext.equals(".midi")) mime = "music/crescendo";
			else if(ext.equals(".midi")) mime = "x-music/x-midi";
			else if(ext.equals(".mif")) mime = "application/x-frame";
			else if(ext.equals(".mif")) mime = "application/x-mif";
			else if(ext.equals(".mime")) mime = "message/rfc822";
			else if(ext.equals(".mime")) mime = "www/mime";
			else if(ext.equals(".mjf")) mime = "audio/x-vnd.audioexplosion.mjuicemediafile";
			else if(ext.equals(".mjpg")) mime = "video/x-motion-jpeg";
			else if(ext.equals(".mm")) mime = "application/base64";
			else if(ext.equals(".mm")) mime = "application/x-meme";
			else if(ext.equals(".mme")) mime = "application/base64";
			else if(ext.equals(".mod")) mime = "audio/mod";
			else if(ext.equals(".mod")) mime = "audio/x-mod";
			else if(ext.equals(".moov")) mime = "video/quicktime";
			else if(ext.equals(".mov")) mime = "video/quicktime";
			else if(ext.equals(".movie")) mime = "video/x-sgi-movie";
			else if(ext.equals(".mp2")) mime = "audio/mpeg";
			else if(ext.equals(".mp2")) mime = "audio/x-mpeg";
			else if(ext.equals(".mp2")) mime = "video/mpeg";
			else if(ext.equals(".mp2")) mime = "video/x-mpeg";
			else if(ext.equals(".mp2")) mime = "video/x-mpeq2a";
			else if(ext.equals(".mp3")) mime = "audio/mpeg3";
			else if(ext.equals(".mp3")) mime = "audio/x-mpeg-3";
			else if(ext.equals(".mp3")) mime = "video/mpeg";
			else if(ext.equals(".mp3")) mime = "video/x-mpeg";
			else if(ext.equals(".mpa")) mime = "audio/mpeg";
			else if(ext.equals(".mpa")) mime = "video/mpeg";
			else if(ext.equals(".mpc")) mime = "application/x-project";
			else if(ext.equals(".mpe")) mime = "video/mpeg";
			else if(ext.equals(".mpeg")) mime = "video/mpeg";
			else if(ext.equals(".mpg")) mime = "audio/mpeg";
			else if(ext.equals(".mpg")) mime = "video/mpeg";
			else if(ext.equals(".mpga")) mime = "audio/mpeg";
			else if(ext.equals(".mpp")) mime = "application/vnd.ms-project";
			else if(ext.equals(".mpt")) mime = "application/x-project";
			else if(ext.equals(".mpv")) mime = "application/x-project";
			else if(ext.equals(".mpx")) mime = "application/x-project";
			else if(ext.equals(".mrc")) mime = "application/marc";
			else if(ext.equals(".ms")) mime = "application/x-troff-ms";
			else if(ext.equals(".mv")) mime = "video/x-sgi-movie";
			else if(ext.equals(".my")) mime = "audio/make";
			else if(ext.equals(".mzz")) mime = "application/x-vnd.audioexplosion.mzz";
			else if(ext.equals(".nap")) mime = "image/naplps";
			else if(ext.equals(".naplps")) mime = "image/naplps";
			else if(ext.equals(".nc")) mime = "application/x-netcdf";
			else if(ext.equals(".ncm")) mime = "application/vnd.nokia.configuration-message";
			else if(ext.equals(".nif")) mime = "image/x-niff";
			else if(ext.equals(".niff")) mime = "image/x-niff";
			else if(ext.equals(".nix")) mime = "application/x-mix-transfer";
			else if(ext.equals(".nsc")) mime = "application/x-conference";
			else if(ext.equals(".nvd")) mime = "application/x-navidoc";
			else if(ext.equals(".o")) mime = "application/octet-stream";
			else if(ext.equals(".oda")) mime = "application/oda";
			else if(ext.equals(".omc")) mime = "application/x-omc";
			else if(ext.equals(".omcd")) mime = "application/x-omcdatamaker";
			else if(ext.equals(".omcr")) mime = "application/x-omcregerator";
			else if(ext.equals(".p")) mime = "text/x-pascal";
			else if(ext.equals(".p10")) mime = "application/pkcs10";
			else if(ext.equals(".p10")) mime = "application/x-pkcs10";
			else if(ext.equals(".p12")) mime = "application/pkcs-12";
			else if(ext.equals(".p12")) mime = "application/x-pkcs12";
			else if(ext.equals(".p7a")) mime = "application/x-pkcs7-signature";
			else if(ext.equals(".p7c")) mime = "application/pkcs7-mime";
			else if(ext.equals(".p7c")) mime = "application/x-pkcs7-mime";
			else if(ext.equals(".p7m")) mime = "application/pkcs7-mime";
			else if(ext.equals(".p7m")) mime = "application/x-pkcs7-mime";
			else if(ext.equals(".p7r")) mime = "application/x-pkcs7-certreqresp";
			else if(ext.equals(".p7s")) mime = "application/pkcs7-signature";
			else if(ext.equals(".part")) mime = "application/pro_eng";
			else if(ext.equals(".pas")) mime = "text/pascal";
			else if(ext.equals(".pbm")) mime = "image/x-portable-bitmap";
			else if(ext.equals(".pcl")) mime = "application/vnd.hp-pcl";
			else if(ext.equals(".pcl")) mime = "application/x-pcl";
			else if(ext.equals(".pct")) mime = "image/x-pict";
			else if(ext.equals(".pcx")) mime = "image/x-pcx";
			else if(ext.equals(".pdb")) mime = "chemical/x-pdb";
			else if(ext.equals(".pdf")) mime = "application/pdf";
			else if(ext.equals(".pfunk")) mime = "audio/make";
			else if(ext.equals(".pfunk")) mime = "audio/make.my.funk";
			else if(ext.equals(".pgm")) mime = "image/x-portable-graymap";
			else if(ext.equals(".pgm")) mime = "image/x-portable-greymap";
			else if(ext.equals(".pic")) mime = "image/pict";
			else if(ext.equals(".pict")) mime = "image/pict";
			else if(ext.equals(".pkg")) mime = "application/x-newton-compatible-pkg";
			else if(ext.equals(".pko")) mime = "application/vnd.ms-pki.pko";
			else if(ext.equals(".pl")) mime = "text/plain";
			else if(ext.equals(".pl")) mime = "text/x-script.perl";
			else if(ext.equals(".plx")) mime = "application/x-pixclscript";
			else if(ext.equals(".pm")) mime = "image/x-xpixmap";
			else if(ext.equals(".pm")) mime = "text/x-script.perl-module";
			else if(ext.equals(".pm4")) mime = "application/x-pagemaker";
			else if(ext.equals(".pm5")) mime = "application/x-pagemaker";
			else if(ext.equals(".png")) mime = "image/png";
			else if(ext.equals(".pnm")) mime = "application/x-portable-anymap";
			else if(ext.equals(".pnm")) mime = "image/x-portable-anymap";
			else if(ext.equals(".pot")) mime = "application/mspowerpoint";
			else if(ext.equals(".pot")) mime = "application/vnd.ms-powerpoint";
			else if(ext.equals(".pov")) mime = "model/x-pov";
			else if(ext.equals(".ppa")) mime = "application/vnd.ms-powerpoint";
			else if(ext.equals(".ppm")) mime = "image/x-portable-pixmap";
			else if(ext.equals(".pps")) mime = "application/mspowerpoint";
			else if(ext.equals(".pps")) mime = "application/vnd.ms-powerpoint";
			else if(ext.equals(".ppt")) mime = "application/mspowerpoint";
			else if(ext.equals(".ppt")) mime = "application/powerpoint";
			else if(ext.equals(".ppt")) mime = "application/vnd.ms-powerpoint";
			else if(ext.equals(".ppt")) mime = "application/x-mspowerpoint";
			else if(ext.equals(".ppz")) mime = "application/mspowerpoint";
			else if(ext.equals(".pre")) mime = "application/x-freelance";
			else if(ext.equals(".prt")) mime = "application/pro_eng";
			else if(ext.equals(".ps")) mime = "application/postscript";
			else if(ext.equals(".psd")) mime = "application/octet-stream";
			else if(ext.equals(".pvu")) mime = "paleovu/x-pv";
			else if(ext.equals(".pwz")) mime = "application/vnd.ms-powerpoint";
			else if(ext.equals(".py")) mime = "text/x-script.phyton";
			else if(ext.equals(".pyc")) mime = "application/x-bytecode.python";
			else if(ext.equals(".qcp")) mime = "audio/vnd.qcelp";
			else if(ext.equals(".qd3")) mime = "x-world/x-3dmf";
			else if(ext.equals(".qd3d")) mime = "x-world/x-3dmf";
			else if(ext.equals(".qif")) mime = "image/x-quicktime";
			else if(ext.equals(".qt")) mime = "video/quicktime";
			else if(ext.equals(".qtc")) mime = "video/x-qtc";
			else if(ext.equals(".qti")) mime = "image/x-quicktime";
			else if(ext.equals(".qtif")) mime = "image/x-quicktime";
			else if(ext.equals(".ra")) mime = "audio/x-pn-realaudio";
			else if(ext.equals(".ra")) mime = "audio/x-pn-realaudio-plugin";
			else if(ext.equals(".ra")) mime = "audio/x-realaudio";
			else if(ext.equals(".ram")) mime = "audio/x-pn-realaudio";
			else if(ext.equals(".ras")) mime = "application/x-cmu-raster";
			else if(ext.equals(".ras")) mime = "image/cmu-raster";
			else if(ext.equals(".ras")) mime = "image/x-cmu-raster";
			else if(ext.equals(".rast")) mime = "image/cmu-raster";
			else if(ext.equals(".rexx")) mime = "text/x-script.rexx";
			else if(ext.equals(".rf")) mime = "image/vnd.rn-realflash";
			else if(ext.equals(".rgb")) mime = "image/x-rgb";
			else if(ext.equals(".rm")) mime = "application/vnd.rn-realmedia";
			else if(ext.equals(".rm")) mime = "audio/x-pn-realaudio";
			else if(ext.equals(".rmi")) mime = "audio/mid";
			else if(ext.equals(".rmm")) mime = "audio/x-pn-realaudio";
			else if(ext.equals(".rmp")) mime = "audio/x-pn-realaudio";
			else if(ext.equals(".rmp")) mime = "audio/x-pn-realaudio-plugin";
			else if(ext.equals(".rng")) mime = "application/ringing-tones";
			else if(ext.equals(".rng")) mime = "application/vnd.nokia.ringing-tone";
			else if(ext.equals(".rnx")) mime = "application/vnd.rn-realplayer";
			else if(ext.equals(".roff")) mime = "application/x-troff";
			else if(ext.equals(".rp")) mime = "image/vnd.rn-realpix";
			else if(ext.equals(".rpm")) mime = "audio/x-pn-realaudio-plugin";
			else if(ext.equals(".rt")) mime = "text/richtext";
			else if(ext.equals(".rt")) mime = "text/vnd.rn-realtext";
			else if(ext.equals(".rtf")) mime = "application/rtf";
			else if(ext.equals(".rtf")) mime = "application/x-rtf";
			else if(ext.equals(".rtf")) mime = "text/richtext";
			else if(ext.equals(".rtx")) mime = "application/rtf";
			else if(ext.equals(".rtx")) mime = "text/richtext";
			else if(ext.equals(".rv")) mime = "video/vnd.rn-realvideo";
			else if(ext.equals(".s")) mime = "text/x-asm";
			else if(ext.equals(".s3m")) mime = "audio/s3m";
			else if(ext.equals(".saveme")) mime = "application/octet-stream";
			else if(ext.equals(".sbk")) mime = "application/x-tbook";
			else if(ext.equals(".scm")) mime = "application/x-lotusscreencam";
			else if(ext.equals(".scm")) mime = "text/x-script.guile";
			else if(ext.equals(".scm")) mime = "text/x-script.scheme";
			else if(ext.equals(".scm")) mime = "video/x-scm";
			else if(ext.equals(".sdml")) mime = "text/plain";
			else if(ext.equals(".sdp")) mime = "application/sdp";
			else if(ext.equals(".sdp")) mime = "application/x-sdp";
			else if(ext.equals(".sdr")) mime = "application/sounder";
			else if(ext.equals(".sea")) mime = "application/sea";
			else if(ext.equals(".sea")) mime = "application/x-sea";
			else if(ext.equals(".set")) mime = "application/set";
			else if(ext.equals(".sgm")) mime = "text/sgml";
			else if(ext.equals(".sgm")) mime = "text/x-sgml";
			else if(ext.equals(".sgml")) mime = "text/sgml";
			else if(ext.equals(".sgml")) mime = "text/x-sgml";
			else if(ext.equals(".sh")) mime = "application/x-bsh";
			else if(ext.equals(".sh")) mime = "application/x-sh";
			else if(ext.equals(".sh")) mime = "application/x-shar";
			else if(ext.equals(".sh")) mime = "text/x-script.sh";
			else if(ext.equals(".shar")) mime = "application/x-bsh";
			else if(ext.equals(".shar")) mime = "application/x-shar";
			else if(ext.equals(".shtml")) mime = "text/html";
			else if(ext.equals(".shtml")) mime = "text/x-server-parsed-html";
			else if(ext.equals(".sid")) mime = "audio/x-psid";
			else if(ext.equals(".sit")) mime = "application/x-sit";
			else if(ext.equals(".sit")) mime = "application/x-stuffit";
			else if(ext.equals(".skd")) mime = "application/x-koan";
			else if(ext.equals(".skm")) mime = "application/x-koan";
			else if(ext.equals(".skp")) mime = "application/x-koan";
			else if(ext.equals(".skt")) mime = "application/x-koan";
			else if(ext.equals(".sl")) mime = "application/x-seelogo";
			else if(ext.equals(".smi")) mime = "application/smil";
			else if(ext.equals(".smil")) mime = "application/smil";
			else if(ext.equals(".snd")) mime = "audio/basic";
			else if(ext.equals(".snd")) mime = "audio/x-adpcm";
			else if(ext.equals(".sol")) mime = "application/solids";
			else if(ext.equals(".spc")) mime = "application/x-pkcs7-certificates";
			else if(ext.equals(".spc")) mime = "text/x-speech";
			else if(ext.equals(".spl")) mime = "application/futuresplash";
			else if(ext.equals(".spr")) mime = "application/x-sprite";
			else if(ext.equals(".sprite")) mime = "application/x-sprite";
			else if(ext.equals(".src")) mime = "application/x-wais-source";
			else if(ext.equals(".ssi")) mime = "text/x-server-parsed-html";
			else if(ext.equals(".ssm")) mime = "application/streamingmedia";
			else if(ext.equals(".sst")) mime = "application/vnd.ms-pki.certstore";
			else if(ext.equals(".step")) mime = "application/step";
			else if(ext.equals(".stl")) mime = "application/sla";
			else if(ext.equals(".stl")) mime = "application/vnd.ms-pki.stl";
			else if(ext.equals(".stl")) mime = "application/x-navistyle";
			else if(ext.equals(".stp")) mime = "application/step";
			else if(ext.equals(".sv4cpio")) mime = "application/x-sv4cpio";
			else if(ext.equals(".sv4crc")) mime = "application/x-sv4crc";
			else if(ext.equals(".svf")) mime = "image/vnd.dwg";
			else if(ext.equals(".svf")) mime = "image/x-dwg";
			else if(ext.equals(".svr")) mime = "application/x-world";
			else if(ext.equals(".svr")) mime = "x-world/x-svr";
			else if(ext.equals(".swf")) mime = "application/x-shockwave-flash";
			else if(ext.equals(".t")) mime = "application/x-troff";
			else if(ext.equals(".talk")) mime = "text/x-speech";
			else if(ext.equals(".tar")) mime = "application/x-tar";
			else if(ext.equals(".tbk")) mime = "application/toolbook";
			else if(ext.equals(".tbk")) mime = "application/x-tbook";
			else if(ext.equals(".tcl")) mime = "application/x-tcl";
			else if(ext.equals(".tcl")) mime = "text/x-script.tcl";
			else if(ext.equals(".tcsh")) mime = "text/x-script.tcsh";
			else if(ext.equals(".tex")) mime = "application/x-tex";
			else if(ext.equals(".texi")) mime = "application/x-texinfo";
			else if(ext.equals(".texinfo")) mime = "application/x-texinfo";
			else if(ext.equals(".text")) mime = "application/plain";
			else if(ext.equals(".text")) mime = "text/plain";
			else if(ext.equals(".tgz")) mime = "application/gnutar";
			else if(ext.equals(".tgz")) mime = "application/x-compressed";
			else if(ext.equals(".tif")) mime = "image/tiff";
			else if(ext.equals(".tif")) mime = "image/x-tiff";
			else if(ext.equals(".tiff")) mime = "image/tiff";
			else if(ext.equals(".tiff")) mime = "image/x-tiff";
			else if(ext.equals(".tr")) mime = "application/x-troff";
			else if(ext.equals(".tsi")) mime = "audio/tsp-audio";
			else if(ext.equals(".tsp")) mime = "application/dsptype";
			else if(ext.equals(".tsp")) mime = "audio/tsplayer";
			else if(ext.equals(".tsv")) mime = "text/tab-separated-values";
			else if(ext.equals(".turbot")) mime = "image/florian";
			else if(ext.equals(".txt")) mime = "text/plain";
			else if(ext.equals(".uil")) mime = "text/x-uil";
			else if(ext.equals(".uni")) mime = "text/uri-list";
			else if(ext.equals(".unis")) mime = "text/uri-list";
			else if(ext.equals(".unv")) mime = "application/i-deas";
			else if(ext.equals(".uri")) mime = "text/uri-list";
			else if(ext.equals(".uris")) mime = "text/uri-list";
			else if(ext.equals(".ustar")) mime = "application/x-ustar";
			else if(ext.equals(".ustar")) mime = "multipart/x-ustar";
			else if(ext.equals(".uu")) mime = "application/octet-stream";
			else if(ext.equals(".uu")) mime = "text/x-uuencode";
			else if(ext.equals(".uue")) mime = "text/x-uuencode";
			else if(ext.equals(".vcd")) mime = "application/x-cdlink";
			else if(ext.equals(".vcs")) mime = "text/x-vcalendar";
			else if(ext.equals(".vda")) mime = "application/vda";
			else if(ext.equals(".vdo")) mime = "video/vdo";
			else if(ext.equals(".vew")) mime = "application/groupwise";
			else if(ext.equals(".viv")) mime = "video/vivo";
			else if(ext.equals(".viv")) mime = "video/vnd.vivo";
			else if(ext.equals(".vivo")) mime = "video/vivo";
			else if(ext.equals(".vivo")) mime = "video/vnd.vivo";
			else if(ext.equals(".vmd")) mime = "application/vocaltec-media-desc";
			else if(ext.equals(".vmf")) mime = "application/vocaltec-media-file";
			else if(ext.equals(".voc")) mime = "audio/voc";
			else if(ext.equals(".voc")) mime = "audio/x-voc";
			else if(ext.equals(".vos")) mime = "video/vosaic";
			else if(ext.equals(".vox")) mime = "audio/voxware";
			else if(ext.equals(".vqe")) mime = "audio/x-twinvq-plugin";
			else if(ext.equals(".vqf")) mime = "audio/x-twinvq";
			else if(ext.equals(".vql")) mime = "audio/x-twinvq-plugin";
			else if(ext.equals(".vrml")) mime = "application/x-vrml";
			else if(ext.equals(".vrml")) mime = "model/vrml";
			else if(ext.equals(".vrml")) mime = "x-world/x-vrml";
			else if(ext.equals(".vrt")) mime = "x-world/x-vrt";
			else if(ext.equals(".vsd")) mime = "application/x-visio";
			else if(ext.equals(".vst")) mime = "application/x-visio";
			else if(ext.equals(".vsw")) mime = "application/x-visio";
			else if(ext.equals(".w60")) mime = "application/wordperfect6.0";
			else if(ext.equals(".w61")) mime = "application/wordperfect6.1";
			else if(ext.equals(".w6w")) mime = "application/msword";
			else if(ext.equals(".wav")) mime = "audio/wav";
			else if(ext.equals(".wav")) mime = "audio/x-wav";
			else if(ext.equals(".wb1")) mime = "application/x-qpro";
			else if(ext.equals(".wbmp")) mime = "image/vnd.wap.wbmp";
			else if(ext.equals(".web")) mime = "application/vnd.xara";
			else if(ext.equals(".wiz")) mime = "application/msword";
			else if(ext.equals(".wk1")) mime = "application/x-123";
			else if(ext.equals(".wmf")) mime = "windows/metafile";
			else if(ext.equals(".wml")) mime = "text/vnd.wap.wml";
			else if(ext.equals(".wmlc")) mime = "application/vnd.wap.wmlc";
			else if(ext.equals(".wmls")) mime = "text/vnd.wap.wmlscript";
			else if(ext.equals(".wmlsc")) mime = "application/vnd.wap.wmlscriptc";
			else if(ext.equals(".word")) mime = "application/msword";
			else if(ext.equals(".wp")) mime = "application/wordperfect";
			else if(ext.equals(".wp5")) mime = "application/wordperfect";
			else if(ext.equals(".wp5")) mime = "application/wordperfect6.0";
			else if(ext.equals(".wp6")) mime = "application/wordperfect";
			else if(ext.equals(".wpd")) mime = "application/wordperfect";
			else if(ext.equals(".wpd")) mime = "application/x-wpwin";
			else if(ext.equals(".wq1")) mime = "application/x-lotus";
			else if(ext.equals(".wri")) mime = "application/mswrite";
			else if(ext.equals(".wri")) mime = "application/x-wri";
			else if(ext.equals(".wrl")) mime = "application/x-world";
			else if(ext.equals(".wrl")) mime = "model/vrml";
			else if(ext.equals(".wrl")) mime = "x-world/x-vrml";
			else if(ext.equals(".wrz")) mime = "model/vrml";
			else if(ext.equals(".wrz")) mime = "x-world/x-vrml";
			else if(ext.equals(".wsc")) mime = "text/scriplet";
			else if(ext.equals(".wsrc")) mime = "application/x-wais-source";
			else if(ext.equals(".wtk")) mime = "application/x-wintalk";
			else if(ext.equals(".xbm")) mime = "image/x-xbitmap";
			else if(ext.equals(".xbm")) mime = "image/x-xbm";
			else if(ext.equals(".xbm")) mime = "image/xbm";
			else if(ext.equals(".xdr")) mime = "video/x-amt-demorun";
			else if(ext.equals(".xgz")) mime = "xgl/drawing";
			else if(ext.equals(".xif")) mime = "image/vnd.xiff";
			else if(ext.equals(".xl")) mime = "application/excel";
			else if(ext.equals(".xla")) mime = "application/excel";
			else if(ext.equals(".xla")) mime = "application/x-excel";
			else if(ext.equals(".xla")) mime = "application/x-msexcel";
			else if(ext.equals(".xlb")) mime = "application/excel";
			else if(ext.equals(".xlb")) mime = "application/vnd.ms-excel";
			else if(ext.equals(".xlb")) mime = "application/x-excel";
			else if(ext.equals(".xlc")) mime = "application/excel";
			else if(ext.equals(".xlc")) mime = "application/vnd.ms-excel";
			else if(ext.equals(".xlc")) mime = "application/x-excel";
			else if(ext.equals(".xld")) mime = "application/excel";
			else if(ext.equals(".xld")) mime = "application/x-excel";
			else if(ext.equals(".xlk")) mime = "application/excel";
			else if(ext.equals(".xlk")) mime = "application/x-excel";
			else if(ext.equals(".xll")) mime = "application/excel";
			else if(ext.equals(".xll")) mime = "application/vnd.ms-excel";
			else if(ext.equals(".xll")) mime = "application/x-excel";
			else if(ext.equals(".xlm")) mime = "application/excel";
			else if(ext.equals(".xlm")) mime = "application/vnd.ms-excel";
			else if(ext.equals(".xlm")) mime = "application/x-excel";
			else if(ext.equals(".xls")) mime = "application/excel";
			else if(ext.equals(".xls")) mime = "application/vnd.ms-excel";
			else if(ext.equals(".xls")) mime = "application/x-excel";
			else if(ext.equals(".xls")) mime = "application/x-msexcel";
			else if(ext.equals(".xlt")) mime = "application/excel";
			else if(ext.equals(".xlt")) mime = "application/x-excel";
			else if(ext.equals(".xlv")) mime = "application/excel";
			else if(ext.equals(".xlv")) mime = "application/x-excel";
			else if(ext.equals(".xlw")) mime = "application/excel";
			else if(ext.equals(".xlw")) mime = "application/vnd.ms-excel";
			else if(ext.equals(".xlw")) mime = "application/x-excel";
			else if(ext.equals(".xlw")) mime = "application/x-msexcel";
			else if(ext.equals(".xm")) mime = "audio/xm";
			else if(ext.equals(".xml")) mime = "application/xml";
			else if(ext.equals(".xml")) mime = "text/xml";
			else if(ext.equals(".xmz")) mime = "xgl/movie";
			else if(ext.equals(".xpix")) mime = "application/x-vnd.ls-xpix";
			else if(ext.equals(".xpm")) mime = "image/x-xpixmap";
			else if(ext.equals(".xpm")) mime = "image/xpm";
			else if(ext.equals(".x-png")) mime = "image/png";
			else if(ext.equals(".xsr")) mime = "video/x-amt-showrun";
			else if(ext.equals(".xwd")) mime = "image/x-xwd";
			else if(ext.equals(".xwd")) mime = "image/x-xwindowdump";
			else if(ext.equals(".xyz")) mime = "chemical/x-pdb";
			else if(ext.equals(".z")) mime = "application/x-compress";
			else if(ext.equals(".z")) mime = "application/x-compressed";
			else if(ext.equals(".zip")) mime = "application/x-compressed";
			else if(ext.equals(".zip")) mime = "application/x-zip-compressed";
			else if(ext.equals(".zip")) mime = "application/zip";
			else if(ext.equals(".zip")) mime = "multipart/x-zip";
			else if(ext.equals(".zoo")) mime = "application/octet-stream";
			else if(ext.equals(".zsh")) mime = "text/x-script.zsh";
		}catch(Exception e){
			mime = "application/octet-stream";
		}
		return mime;
	}
	
	/*
	 * This method allows to send byte[] by request type POST
	 * 
	 * Params: 
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * Bytes: bytes to send
	 * Filename: filename to send
	 * */
	public String sendFile(String url, Hashtable<String,String> headers, byte[] bytes, String filename){
		String content = null;
		int upload = 0;
		try{
			HttpURLConnection conn = getURLConnection(url, false);
			if(headers != null && headers.size()>0) addHeaders(conn, headers);
			conn.setRequestProperty("Connection", "Keep-Alive");
			conn.setRequestProperty("Cache-Control", "no-cache");
			conn.setRequestProperty("Content-Type", "multipart/form-data;boundary=" + BOUNDARY);
			
			DataOutputStream request = new DataOutputStream(conn.getOutputStream());
			request.writeBytes(TWO_HYPHENS + BOUNDARY + CRLF);
			String attachmentFileName = filename;
			String attachmentName = attachmentFileName.substring(0, attachmentFileName.lastIndexOf("."));
			request.writeBytes("Content-Type: " + getMimeType(filename) + CRLF);
			request.writeBytes("Content-Disposition: form-data; name=\"" + attachmentName + "\";filename=\"" + attachmentFileName + "\"" + CRLF);
			request.writeBytes(CRLF);
			
			if(bytes != null && bytes.length >0){
				request.write(bytes);
				upload += bytes.length;
			}
			
			request.writeBytes(CRLF);
			request.writeBytes(TWO_HYPHENS + BOUNDARY + CRLF);
			request.flush();
			request.close();
			
			content = getTextContent(conn);
			
		}catch(Exception e){
			content = null;
		}
		if(USES_TRAFFIC_ANALYSIS) {
			int download = (content != null && content.length()>0)? content.getBytes().length: 0;
			appendTraficAnalysis(url, download, upload, responseCode, responseMessage);
		}
		return content;
	}
	
	/*
	 * This method allows to send an file by request type POST
	 * 
	 * Params: 
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * Is: resource inputstream to send
	 * Filename: filename to send
	 * */
	public String sendFile(String url, Hashtable<String,String> headers, InputStream is, String filename){
		String content = null;
		int upload = 0;
		try{
			HttpURLConnection conn = getURLConnection(url, false);
			if(headers != null && headers.size()>0) addHeaders(conn, headers);
			conn.setRequestProperty("Connection", "Keep-Alive");
			conn.setRequestProperty("Cache-Control", "no-cache");
			conn.setRequestProperty("Content-Type", "multipart/form-data;boundary=" + BOUNDARY);
			
			DataOutputStream request = new DataOutputStream(conn.getOutputStream());
			request.writeBytes(TWO_HYPHENS + BOUNDARY + CRLF);
			String attachmentFileName = filename;
			String attachmentName = attachmentFileName.substring(0, attachmentFileName.lastIndexOf("."));
			request.writeBytes("Content-Type: " + getMimeType(filename) + CRLF);
			request.writeBytes("Content-Disposition: form-data; name=\"" + attachmentName + "\";filename=\"" + attachmentFileName + "\"" + CRLF);
			request.writeBytes(CRLF);
			
			int size = (int) is.available();
			if(size >0){
				byte[] bytes = new byte[1024];
				int numRead = 0;
				while ((numRead = is.read(bytes)) >= 0) {
					request.write(bytes, 0, numRead);
					upload += numRead;
				}
				is.close();
			}
			
			request.writeBytes(CRLF);
			request.writeBytes(TWO_HYPHENS + BOUNDARY + CRLF);
			request.flush();
			request.close();
			
			content = getTextContent(conn);
			
		}catch(Exception e){
			content = null;
		}
		if(USES_TRAFFIC_ANALYSIS) {
			int download = (content != null && content.length()>0)? content.getBytes().length: 0;
			appendTraficAnalysis(url, download, upload, responseCode, responseMessage);
		}
		return content;
	}
	
	/*
	 * This method allows to send an file by request type POST
	 * 
	 * Params: 
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * File: file to send
	 * */
	public String sendFile(String url, Hashtable<String,String> headers, File file){
		String content = null;
		int upload = 0;
		try{
			HttpURLConnection conn = getURLConnection(url, false);
			if(headers != null && headers.size()>0) addHeaders(conn, headers);
			conn.setRequestProperty("Connection", "Keep-Alive");
			conn.setRequestProperty("Cache-Control", "no-cache");
			conn.setRequestProperty("Content-Type", "multipart/form-data;boundary=" + BOUNDARY);
			
			DataOutputStream request = new DataOutputStream(conn.getOutputStream());
			request.writeBytes(TWO_HYPHENS + BOUNDARY + CRLF);
			String attachmentFileName = file.getName();
			String attachmentName = attachmentFileName.substring(0, attachmentFileName.lastIndexOf("."));
			request.writeBytes("Content-Type: " + getMimeType(file.getName()) + CRLF);
			request.writeBytes("Content-Disposition: form-data; name=\"" + attachmentName + "\";filename=\"" + attachmentFileName + "\"" + CRLF);
			request.writeBytes(CRLF);
			
			int size = (int) file.length();
			if(size >0){
				InputStream fis = new FileInputStream(file);
				byte[] bytes = new byte[1024];
				int numRead = 0;
				while ((numRead = fis.read(bytes)) >= 0) {
					request.write(bytes, 0, numRead);
					upload += numRead;
				}
				fis.close();
			}
			
			request.writeBytes(CRLF);
			request.writeBytes(TWO_HYPHENS + BOUNDARY + CRLF);
			request.flush();
			request.close();
			
			content = getTextContent(conn);
			
		}catch(Exception e){
			content = null;
		}
		if(USES_TRAFFIC_ANALYSIS) {
			int download = (content != null && content.length()>0)? content.getBytes().length: 0;
			appendTraficAnalysis(url, download, upload, responseCode, responseMessage);
		}
		return content;
	}

	/*
	 * This method allows to send a request type JSON
	 * 
	 * Params: 
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * Json: body json for send
	 * */
	public String sendJSON(String url, Hashtable<String,String> headers, String json){
		String content = null;
		try{
			if(json.length()>0){
				HttpURLConnection conn = getURLConnection(url, false);
				if(headers != null && headers.size()>0) addHeaders(conn, headers);
				addPostJson(conn, json, false);
				content = getTextContent(conn);
			}
		}catch(Exception e){
			content = null;
		}
		if(USES_TRAFFIC_ANALYSIS) {
			int download = (content != null && content.length()>0)? content.getBytes().length: 0;
			int upload = (json != null && json.length()>0)? json.getBytes().length: 0;
			appendTraficAnalysis(url, download, upload, responseCode, responseMessage);
		}
		return content;
	}

	/*
	 * This method allows to send a request type POST
	 * 
	 * Params: 
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * params: parameters that will be sent by POST 
	 * */
	public String sendPOST(String url, Hashtable<String,String> headers, Hashtable<String,String> params){
		String postParameters = null;
		String content = null;
		try{
			if(params.size()>0){
				HttpURLConnection conn = getURLConnection(url, false);
				if(headers != null && headers.size()>0) addHeaders(conn, headers);
				postParameters = addPostVars(conn, params);
				content = getTextContent(conn);
			}
		}catch(Exception e){
			content = null;
		}
		if(USES_TRAFFIC_ANALYSIS) {
			int upload = (postParameters != null && postParameters.length()>0)? postParameters.getBytes().length: 0;
			int download = (content != null && content.length()>0)? content.getBytes().length: 0;
			appendTraficAnalysis(url, download, upload, responseCode, responseMessage);
		}
		return content;
	}

	/*
	 * This method allows to send a request type GET
	 * 
	 * Params: 
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * */
	public String sendGET(String url, Hashtable<String,String> headers){
		String content = null;
		try{
			HttpURLConnection conn = getURLConnection(url, true);
			if(headers != null && headers.size()>0) addHeaders(conn, headers);
			content = getTextContent(conn);
		}catch(Exception e){
			content = null;
		}
		if(USES_TRAFFIC_ANALYSIS) {
			int download = (content != null && content.length()>0)? content.getBytes().length: 0;
			appendTraficAnalysis(url, download, 0, responseCode, responseMessage);
		}
		return content;
	}
	
	/*
	 * This method allows to send a request type JSON
	 * 
	 * Params: 
	 * UsesBypass: enables or disables SSLCerficicate validation
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * Json: body json for send
	 * */
	public static AsyncTask<Object, Object, Object> asynchSendJSON(boolean usesBypass, String url, Hashtable<String,String> headers, String json, IBypassSSLCerficicate callback){
		WebQuery query = new WebQuery("sendJSON", usesBypass, url, headers, null, json, callback);
		query.execute(new Object[]{});
		return query;
	}
	
	/*
	 * This method allows to send a request type POST
	 * 
	 * Params: 
	 * UsesBypass: enables or disables SSLCerficicate validation
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * params: parameters that will be sent by POST 
	 * */
	public static AsyncTask<Object, Object, Object> asynchSendPOST(boolean usesBypass, String url, Hashtable<String,String> headers, Hashtable<String,String> params, IBypassSSLCerficicate callback){
		WebQuery query = new WebQuery("sendPOST", usesBypass, url, headers, params, null, callback);
		query.execute(new Object[]{});
		return query;
	}
	
	/*
	 * This method allows to send a request type GET
	 * 
	 * Params: 
	 * UsesBypass: enables or disables SSLCerficicate validation
	 * Ulr: url of service
	 * Headers: headers with the request will be made
	 * */
	public static AsyncTask<Object, Object, Object> asynchSendGET(boolean usesBypass, String url, Hashtable<String,String> headers, IBypassSSLCerficicate callback){
		WebQuery query = new WebQuery("sendGET", usesBypass, url, headers, null, null, callback);
		query.execute(new Object[]{});
		return query;
	}
	
	//****************************************************************************************************************************
	
	static class WebQuery extends AsyncTask<Object, Object, Object> {

		private Hashtable<String,String> headers = null;
		private Hashtable<String,String> params = null;
		private IBypassSSLCerficicate callback = null;
		private boolean usesBypass = false;
		private String method = null;
		private String json = null;
		private String url = null;
		
		WebQuery(String method, boolean usesBypass, String url, Hashtable<String,String> headers, Hashtable<String,String> params, String json, IBypassSSLCerficicate callback){
			this.url = url;
			this.json = json;
			this.params = params;
			this.headers = headers;
			this.callback = callback;
			
			this.method = method;
			this.usesBypass = usesBypass;
		}
		
		@Override
		protected Object doInBackground(Object... arg) {
			String content = null;
			String message = null;
			int code = -1;
			try{
				BypassSSLCerficicate bypass = BypassSSLCerficicate.getInstance(usesBypass);
				if(method != null){
					if(method.equals("sendJSON")){
						content = bypass.sendJSON(url, headers, json);
						message = bypass.getResponseMessage();
						code = bypass.getResponseCode();
					}
					else if(method.equals("sendPOST")){
						content = bypass.sendPOST(url, headers, params);
						message = bypass.getResponseMessage();
						code = bypass.getResponseCode();
					}
					else if(method.equals("sendGET")){
						content = bypass.sendGET(url, headers);
						message = bypass.getResponseMessage();
						code = bypass.getResponseCode();
					}
				}
			}catch(Exception e){
				content = null;
				message = null;
				code = -1;
			}
			return new Object[]{code, message, content};
		}
		
		protected void onPostExecute (Object result){
			if(result != null && result instanceof Object[] && callback != null){
				Object[] data = (Object[])result;
				String content = (data[2] != null)? data[2].toString():null;
				String message = (data[1] != null)? data[1].toString():null;
				int code = Integer.parseInt(data[0].toString());
				callback.response(code, message, content);
			}
		}
	}

	//****************************************************************************************************************************
	
	public static String[] decodeJsonArray(String source){
        try{
        	JSONArray o = new JSONArray(source);
            int length = o.length();
            if(length>0){
                String[] array = new String[length];
                for(int i=0; i<length; i++){
                    array[i] =o.getString(i);
                }
                return array;
            }
        }catch(Exception e){}
        return null;
    }
    
    public static java.util.Hashtable<String, Object> decodeJsonHashtable(String source){
        java.util.Hashtable<String, Object> table = new java.util.Hashtable<String, Object>(0);
        try{
            JSONObject o = new JSONObject(source);
            int length = o.length();
            if(length > 0){
            	Iterator<String> en =  o.keys();
            	while(en.hasNext()){
                    String key = en.next().toString();
                    String value = o.get(key)+"";
                    table.put(key, value);
                }
            }
        }catch(Exception e){
        	table = new java.util.Hashtable<String, Object>(0);
        }
        return table;
    }
    
    //****************************************************************************************************************************
    
    public Bitmap getBitmap(String url, Hashtable<String,String> headers){
    	Bitmap bmp = null;
    	int download = 0;
    	try{
    		HttpURLConnection conn = getURLConnection(url, false);
			if(headers != null && headers.size()>0) addHeaders(conn, headers);
			InputStream input = conn.getInputStream();
			responseMessage = conn.getResponseMessage();
			responseCode = conn.getResponseCode();
			download = conn.getContentLength();
			if(responseCode == 200){
				bmp = BitmapFactory.decodeStream(input);
			}
		}catch(Exception e){
			bmp = null;
		}
    	if(USES_TRAFFIC_ANALYSIS) {
			appendTraficAnalysis(url, download, 0, responseCode, responseMessage);
		}
    	return bmp;
    }

    //****************************************************************************************************************************

    //XML decoder comming soon ...
    
    //****************************************************************************************************************************
    
}
