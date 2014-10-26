package com.jheto.net;

import android.annotation.SuppressLint;
import android.os.AsyncTask;
import android.util.Log;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;

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

	private void addPostVars(HttpURLConnection conn, Hashtable<String,String> params){
		try{
			String method = conn.getRequestMethod();
			if(method.equals("POST")){
				String urlParameters = "";
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
		String content = null;
		try{
			if(params.size()>0){
				HttpURLConnection conn = getURLConnection(url, false);
				if(headers != null && headers.size()>0) addHeaders(conn, headers);
				addPostVars(conn, params);
				content = getTextContent(conn);
			}
		}catch(Exception e){
			content = null;
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
            	Iterator<Object> en =  o.keys();
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

    //XML decoder comming soon ...
    
    //****************************************************************************************************************************
    
}
