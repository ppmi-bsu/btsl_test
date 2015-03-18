btsl_test
=========

Чтобы запустить:

```
1) Установить python
2) Установить пакеты:
pip install -r requirements.txt

3) Создать файл local_settings.py в корне проекта, прописать необходимые переменные
(как минимум, указать путь к бинарнику openssl и путь к библиотеке bee2evp - все пути через прямой слеш)

4) python -m unittest test_openssl test_ca test_certificates test_cms
```
