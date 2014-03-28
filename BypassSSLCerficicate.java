package com.jheto.xekri.util;

import android.annotation.SuppressLint;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
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

	private boolean enableAllCertificates = false;

	private BypassSSLCerficicate(){
	}

	/*
	 * Crea una instancia de la clase
	 * 
	 * Params:
	 * enableAllCertificates: para conexiones por https true activa el bypass con certificados no validos
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
		conn.setConnectTimeout(1000 * 60);
		conn.setReadTimeout(1000 * 60);
		conn.setDoOutput(true);
		conn.setDoInput(true);
		conn.setUseCaches(false);
		if(isGET) conn.setRequestMethod("GET");
		else conn.setRequestMethod("POST");
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
			}catch(Exception e){}
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
		InputStream is = conn.getInputStream();
		byte[] bytes = new byte[1024];
		int numRead = 0;
		while ((numRead = is.read(bytes)) >= 0) {
			content.append(new String(bytes, 0, numRead));
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
		String content = "";
		try{
			if(json.length()>0){
				HttpURLConnection conn = getURLConnection(url, false);
				if(headers != null && headers.size()>0) addHeaders(conn, headers);
				addPostJson(conn, json, false);
				content = getTextContent(conn);
			}
		}catch(Exception e){
			content = "";
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
		String content = "";
		try{
			if(params.size()>0){
				HttpURLConnection conn = getURLConnection(url, false);
				if(headers != null && headers.size()>0) addHeaders(conn, headers);
				addPostVars(conn, params);
				content = getTextContent(conn);
			}
		}catch(Exception e){
			content = "";
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
		String content = "";
		try{
			HttpURLConnection conn = getURLConnection(url, true);
			if(headers != null && headers.size()>0) addHeaders(conn, headers);
			content = getTextContent(conn);
		}catch(Exception e){
			content = "";
		}
		return content;
	}
	
	//***************************************************************************
	
	public static String[] decodeArray(String source){
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
    
    public static java.util.Hashtable<String, Object> decodeHashtable(String source){
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
        }catch(Exception e){}
        return table;
    }

}
