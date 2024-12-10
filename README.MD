## how to run 

python3 -m venv myenv

source myenv/bin/activate

pip install -r requirements

#### 1 (not necessary)
javac -cp /usr/local/lib/pteidlibj.jar CcData.java
java -cp .:/usr/local/lib/pteidlibj.jar -Djava.library.path=/usr/local/lib CcData

#### 2
python3 gen_dcc.py

#### 3
python3 req_dcc.py 

#### 4
python3 gen_min_dcc.py 

#### 5
ython3 check_dcc.py 


