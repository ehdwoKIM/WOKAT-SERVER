package com.sopt.wokat.infra.aws;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.PutObjectRequest;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class S3ProfileImageUploader {
    
    private final Logger LOGGER = LogManager.getLogger(this.getClass());
    private final AmazonS3Client amazonS3Client;

    @Value("${cloud.aws.s3.buckets.bucket1}")
    public String bucket;

    public String uploadObject(MultipartFile multipartFile, String storedFileName) throws IOException {

		String filePath = "/" + storedFileName;
		// 1. bucket name, 2. key : full path to the file 3. file : new File로 생성한 file instance  
		// 2. PutObjectRequest로 구현 가능 
		amazonS3Client.putObject(new PutObjectRequest(bucket, filePath, multipartFile.getInputStream(), null));
		
		return amazonS3Client.getUrl(bucket, filePath).toString();
	}

	public void deleteObject( String storedFileName) throws AmazonServiceException {
		amazonS3Client.deleteObject(new DeleteObjectRequest(bucket + "/" , storedFileName));
	}


    public File downloadImage(String imageUrl, String fileName) {
		URL url;
		InputStream is;
		OutputStream os;

		try {
			url = new URL(imageUrl);
			is = url.openStream();
			os = new FileOutputStream(fileName);
			
			byte[] buffer = new byte[1024*16];
			
			while (true) {
				int inputData = is.read(buffer);
				if(inputData == -1) break;
				os.write(buffer,0,inputData);
			}

			is.close();
			os.close();
		} catch (IOException e) {
			e.printStackTrace();
		} 
		return new File(fileName);
	}

}
