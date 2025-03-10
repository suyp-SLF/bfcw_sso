package kd.bos.login.thirdauth.app.sso;

import com.google.common.io.CharStreams;
import com.kingdee.eas.cp.eip.sso.util.BASE64Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URLDecoder;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import kd.bos.actiondispatcher.ActionUtil;
import kd.bos.context.RequestContext;
import kd.bos.dataentity.entity.DynamicObject;
import kd.bos.dataentity.resource.ResManager;
import kd.bos.dc.api.model.Account;
import kd.bos.dc.utils.AccountUtils;
import kd.bos.entity.MainEntityType;
import kd.bos.exception.ErrorCode;
import kd.bos.exception.KDException;
import kd.bos.exception.LoginErrorCode;
import kd.bos.lang.Lang;
import kd.bos.logging.Log;
import kd.bos.logging.LogFactory;
import kd.bos.login.LoginClientEnum;
import kd.bos.login.LoginType;
import kd.bos.login.lang.LoginLangUtils;
import kd.bos.login.thirdauth.ThirdSSOAuthHandler;
import kd.bos.login.thirdauth.UserAuthResult;
import kd.bos.login.thirdauth.UserProperType;
import kd.bos.login.user.LoginUserService;
import kd.bos.login.utils.HttpUtils;
import kd.bos.login.utils.LoginUtils;
import kd.bos.login.utils.SessionUtils;
import kd.bos.orm.query.QCP;
import kd.bos.orm.query.QFilter;
import kd.bos.servicehelper.BusinessDataServiceHelper;
import kd.bos.servicehelper.CodeRuleServiceHelper;
import kd.bos.servicehelper.MetadataServiceHelper;
import kd.bos.servicehelper.operation.OperationServiceHelper;
import kd.bos.servicehelper.operation.SaveServiceHelper;
import kd.bos.tenant.TenantInfo;
import kd.bos.util.ExceptionUtils;
import kd.bos.util.NetAddressUtils;

import org.antlr.v4.parse.ANTLRParser.element_return;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.XMLWriter;

public class NorSSOLoginPlugin implements ThirdSSOAuthHandler {

	@Override
	public void callTrdSSOLogin(HttpServletRequest request, HttpServletResponse response, String callBackUrl) {

		// 用户需要登录的地址
		response.getLocale();
		String thisUrl = "166.111.132.204";
		String loginUrl = "http://" + thisUrl + ":" + "8888"
				+ "/ierp/login.html?logout=false";
		try {
			response.sendRedirect(loginUrl);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public UserAuthResult getTrdSSOAuth(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
		Log logger = LogFactory.getLog(NorSSOLoginPlugin.class);		
		logger.info("====> 1 to do ssoLogin, NorSSOLoginPlugin");
		UserAuthResult result = new UserAuthResult();
		result.setSucess(false);
		boolean isDecode = false;// 判断是否需要转码
	//	this.callTrdSSOLogin(servletRequest,servletResponse,"");
		// 吉大登录
		String dnname = "";
		byte[] radom = null;
		String detach = servletRequest.getParameter("paper");
		logger.info("====> 2 to do ssoLogin, NorSSOLoginPlugin detach:"+detach);
		try {
			radom = servletRequest.getParameter("radom").getBytes();
			logger.info("====> 3 to do ssoLogin, NorSSOLoginPlugin radom:"+radom);
		} catch (Exception e) {
			logger.info("====> 2-1 to do ssoLogin, NorSSOLoginPlugin ex:"+e.getMessage());
			//e.printStackTrace();
			result.setSucess(false);
			result.setErrDesc("");
			return result;
		}
		
		if(StringUtils.isNotEmpty(detach) && null != radom) {
			String remoteAddr = servletRequest.getRemoteAddr();
			String appId = "166.111.132.209";
			String posturl = "https://166.111.60.250:443/MessageService";
			String original = BASE64Util.encode(radom);
			byte[] messagexml = null;
			String respMessageXml = null;
			// 检测信息完整性
			if (StringUtils.isNotEmpty(detach) && StringUtils.isNotEmpty(remoteAddr) && StringUtils.isNotEmpty(appId)
					&& StringUtils.isNotEmpty(original)) {
				/* 封装xml信息 */
				try {
					messagexml = packXml(remoteAddr, appId, detach, original);// 封装xml
					logger.info("====> 4 to do ssoLogin, NorSSOLoginPlugin pack xml false");
				} catch (IOException e) {
					result.setSucess(false);
					result.setErrDesc("封装xml信息失败");
					System.out.println("封装xml信息失败");
					logger.info("====> 5 to do ssoLogin, NorSSOLoginPlugin pack xml false");
				}
				/* 数据包发送 */
				try {
					respMessageXml = postmethod(posturl, messagexml);
				} catch (IOException e) {
					result.setSucess(false);
					result.setErrDesc("发送数据包失败");
					System.out.println("发送数据包失败");
					logger.info("====> 6 to do ssoLogin, NorSSOLoginPlugin send package fasle");
				}
				/* 解析返回数据包 */
				try {
					dnname = sysXml(respMessageXml);
				} catch (DocumentException e) {
					result.setSucess(false);
					result.setErrDesc("解析数据包异常");
					System.out.println("解析数据包异常");
					logger.info("====> 7 to do ssoLogin, NorSSOLoginPlugin parsing package false");
				}
			} else {
				result.setSucess(false);
				result.setErrDesc("获取返回信息失败");
				System.out.println("获取返回信息失败");
				logger.info("====> 8 to do ssoLogin, NorSSOLoginPlugin get backmsg false");
			}

			if (!StringUtils.isEmpty(dnname)) {
				if (isDecode) {
					dnname = decode(URLDecoder.decode(dnname));
				}
				dnname = dnname.substring(dnname.indexOf("T=") + 2, dnname.indexOf(",", dnname.indexOf(",") + 1));
				result.setUserType(UserProperType.UserName);
				result.setUser(dnname);
				// result.setUser(userName);
				result.setJoinedEids(null);
				result.setSucess(true);
			}else {
				logger.info("====> 9 to do ssoLogin, NorSSOLoginPlugin login false");
				result.setSucess(false);
				result.setErrDesc("登录错误");
			}
		}
		return result;
	}

	public String postmethod(String posturl, byte[] messagexml) throws IOException {
		Log logger = LogFactory.getLog(NorSSOLoginPlugin.class);		
		String errCode = null;
		String errDesc = null;
		int statusCode = 0;
		logger.info("========<<<<<1");
		ProtocolSocketFactory fcty = new MySecureProtocolSocketFactory();
		Protocol.registerProtocol("https", new Protocol("https", fcty, 443));
		HttpClient httpClient = new HttpClient();
		CloseableHttpResponse close = null;
		logger.info("========<<<<<2");
		// 创建与网关的HTTP连接，发送认证原文请求报文，并接收认证原文响应报文
		// 创建与网关的HTTP连接开始
		System.out.println("创建与网关的HTTP连接，发送认证原文请求报文开始");
		HttpEntity resultEntity = null;
		PostMethod postMethod = new PostMethod(posturl);
		postMethod.setRequestHeader("Connection", "close");
		logger.info("========<<<<<3");
		// 设置报文传送的编码格式
		postMethod.setRequestHeader("Content-Type", "text/xml;charset=UTF-8");
		// 设置发送认证请求内容开始
		postMethod.setRequestBody(new ByteArrayInputStream(messagexml));
		// 设置发送认证请求内容结束
		// 执行postMethod
		try {
			// 发送原文请求报文与网关通讯
			logger.info("========<<<<<4");
			statusCode = httpClient.executeMethod(postMethod);
		} catch (Exception e) {
			logger.info("========<<<<<5"+e.getMessage());
			e.printStackTrace();
			errCode = String.valueOf(statusCode);
			errDesc = e.getMessage();
			System.out.println("发送原文请求报文与网关连接出现异常：" + errDesc);
			postMethod.releaseConnection();
			httpClient.getHttpConnectionManager().closeIdleConnections(0);
			httpClient = null;
		}
		logger.info("========<<<<<6");
		System.out.println("创建与网关的HTTP连接，发送认证原文请求报文结束");
		// 网关返回认证原文响应
		StringBuffer respMessageData = new StringBuffer();
		String respMessageXml = null;
		// 当返回200或500状态时处理业务逻辑
		if (Integer.valueOf(statusCode) == HttpStatus.SC_OK
				|| Integer.valueOf(statusCode) == HttpStatus.SC_INTERNAL_SERVER_ERROR) {
			try {
				logger.info("========<<<<<7");
				// 接收通讯报文并处理开始
				byte[] input = postMethod.getResponseBody();
				ByteArrayInputStream ByteinputStream = new ByteArrayInputStream(input);
				ByteArrayOutputStream outStream = new ByteArrayOutputStream();
				int ch = 0;
				try {
					while ((ch = ByteinputStream.read()) != -1) {
						int upperCh = (char) ch;
						outStream.write(upperCh);
					}
				} catch (Exception e) {
					logger.info("========<<<<<8"+e.getMessage());
					errDesc = e.getMessage();
				}
				logger.info("========<<<<<9");
				// 200 表示返回处理成功
				if (Integer.valueOf(statusCode) == HttpStatus.SC_OK) {
					logger.info("========<<<<<10");
					respMessageData.append("响应内容开始！\n");
					respMessageData.append(new String(outStream.toByteArray(), "UTF-8") + "\n");
					respMessageData.append("响应内容结束！\n");
					respMessageXml = new String(outStream.toByteArray(), "UTF-8");
				} else {
					logger.info("========<<<<<11");
					// 500 表示返回失败，发生异常
					respMessageData.append("响应500内容开始！\n");
					respMessageData.append(new String(outStream.toByteArray()) + "\n");
					respMessageData.append("响应500内容结束！\n");
					errCode = String.valueOf(statusCode);
					errDesc = new String(outStream.toByteArray());
				}
				System.out.println("网关返回响应内容：" + respMessageData.toString());
			} catch (IOException e) {
				logger.info("========<<<<<12"+e.getMessage());
				errCode = String.valueOf(statusCode);
				errDesc = e.getMessage();
				System.out.println("读取原文请求响应报文出现异常：" + errCode + "," + errDesc);
			} finally {
				if (httpClient != null) {
					postMethod.releaseConnection();
					httpClient.getHttpConnectionManager().closeIdleConnections(0);
					httpClient = null;
				}
			}
		}
		logger.info("========<<<<<13");
		return respMessageXml;

	}

	// 将数据封装成xml，并进行发送
	public byte[] packXml(String remoteAddr, String appId, String detach, String original) throws IOException {
		byte[] messagexml = null;
		System.out.println("组装认证请求报文开始");
		// 组装认证请求报文数据开始
		Document reqDocument = DocumentHelper.createDocument();
		Element root = reqDocument.addElement("message");
		Element requestHeadElement = root.addElement("head");
		Element requestBodyElement = root.addElement("body");

		// 组装报文头信息 ,组装认证xml文件时，进行判断，如果配置调用应用服务器生成原文，则生成xml version版本为1.0，
		// 如果配置从网关生成原文，则生成xml version版本为1.1
		requestHeadElement.addElement("version").setText("1.0");
		// 服务类型
		requestHeadElement.addElement("serviceType").setText("AuthenService");
		// 组装报文体信息
		// 组装客户端信息
		Element clientInfoElement = requestBodyElement.addElement("clientInfo");
		Element clientIPElement = clientInfoElement.addElement("clientIP");
		clientIPElement.setText(remoteAddr);

		// 组装应用标识信息
		requestBodyElement.addElement("appId").setText(appId);
		Element authenElement = requestBodyElement.addElement("authen");
		Element authCredentialElement = authenElement.addElement("authCredential");
		authCredentialElement.addAttribute("authMode", "cert");
		// 组装证书认证信息
		authCredentialElement.addElement("detach").setText(detach);
		authCredentialElement.addElement("original").setText(original);
		// 是否检查访问控制状态
		requestBodyElement.addElement("accessControl").setText("false");
		// 组装属性查询列表信息
		Element attributesElement = requestBodyElement.addElement("attributes");
		attributesElement.addAttribute("attributeType", "all");
		StringBuffer reqMessageData = new StringBuffer();
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		XMLWriter writer = new XMLWriter(outStream);
		writer.write(reqDocument);
		messagexml = outStream.toByteArray();

		reqMessageData.append("请求内容开始！\n");
		reqMessageData.append(outStream.toString() + "\n");
		reqMessageData.append("请求内容结束！\n");
		System.out.println(reqMessageData.toString() + "\n");
		System.out.println("组装认证请求报文结束");
		return messagexml;
	}

	// 解析返回的xml文件
	public String sysXml(String respMessageXml) throws DocumentException {
		Document doc = DocumentHelper.parseText(respMessageXml);
		Element message = doc.getRootElement();
		String status = message.element("body").element("authResultSet").element("authResult")
				.attributeValue("success");
		String dnname = message.element("body").element("attributes").elementText("attr");
		if (StringUtils.isNotEmpty(status) && StringUtils.isNotEmpty(dnname) && "true".equals(status)) {
			return dnname;
		}
		return null;
	}


	/**
	 * @category 字符串编码成Unicode编码
	 */
	private String encode(String src) throws Exception {
		char c;
		StringBuilder str = new StringBuilder();
		int intAsc;
		String strHex;
		for (int i = 0; i < src.length(); i++) {
			c = src.charAt(i);
			intAsc = (int) c;
			strHex = Integer.toHexString(intAsc);
			if (intAsc > 128) {
				str.append("\\u" + strHex);
			} else {
				str.append("\\u00" + strHex); // 低位在前面补00
			}
		}
		return str.toString();
	}

	/**
	 * @category Unicode解码成字符串
	 * @param src
	 * @return
	 */
	private String decode(String src) {
		int t = src.length() / 6;
		StringBuilder str = new StringBuilder();
		for (int i = 0; i < t; i++) {
			String s = src.substring(i * 6, (i + 1) * 6); // 每6位描述一个字节
			// 高位需要补上00再转
			String s1 = s.substring(2, 4) + "00";
			// 低位直接转
			String s2 = s.substring(4);
			// 将16进制的string转为int
			int n = Integer.valueOf(s1, 16) + Integer.valueOf(s2, 16);
			// 将int转换为字符
			char[] chars = Character.toChars(n);
			str.append(new String(chars));
		}
		return str.toString();
	}

}
