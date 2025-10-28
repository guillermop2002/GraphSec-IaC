# Configuración del proveedor AWS (sin credenciales reales para pruebas)
provider "aws" {
  region = "us-east-1"
  # Usar credenciales ficticias para pruebas
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  skip_requesting_account_id = true
}

resource "aws_s3_bucket" "my_test_bucket" {
  bucket = "mi-cubo-de-prueba-tfg-12345"
}

resource "aws_s3_bucket_logging" "logging_config" {
  bucket = aws_s3_bucket.my_test_bucket.id

  target_bucket = "mi-cubo-de-logs-tfg"
  target_prefix = "log/"
}
