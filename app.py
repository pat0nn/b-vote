from flask import Flask , render_template , url_for , redirect , abort , request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin , login_user , LoginManager , login_required , logout_user , current_user
from flask_wtf import FlaskForm
from wtforms import StringField , PasswordField , SubmitField 
from wtforms.validators import InputRequired , Length , ValidationError
from flask_bcrypt import Bcrypt
from credentials import ADMIN , PASSWORD
import json
import time
from hashlib import sha256
import requests
from flask_migrate import Migrate

port = 8000
CONNECTED_SERVICE_ADDRESS = f"http://127.0.0.1:{port}"


app = Flask(__name__)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ===========================================================Login System====================================================================== 


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'THIS IS A SECRET KEY'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.app_context().push()
class User(db.Model , UserMixin):
    id = db.Column(db.Integer , primary_key=True)
    username = db.Column(db.String(20) , nullable=False , unique=True)
    password = db.Column(db.String(80) , nullable=False)
    address  = db.Column(db.String(80) , nullable=False , unique=True)
    key      = db.Column(db.String(80) , nullable=False , unique=True)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired() , Length(min=1 , max=20)], render_kw={"placeholder" : "Username"})
    password = PasswordField(validators=[InputRequired() , Length(min=1 , max=20)], render_kw={"placeholder" : "Password"})
    address = StringField(validators=[InputRequired() , Length(min=4 , max=80)], render_kw={"placeholder" : "address"})
    key = StringField(validators=[InputRequired() , Length(min=4 , max=80)], render_kw={"placeholder" : "key"})

    submit = SubmitField("Register")

    def validate_username(self , username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError(" USERNAME ALREADY EXISTS , PLZ CHOOSE OTHER")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired() , Length(min=1 , max=20)], render_kw={"placeholder" : "Username"})
    password = PasswordField(validators=[InputRequired() , Length(min=1 , max=20)], render_kw={"placeholder" : "Password"})

    submit = SubmitField("Log In")

# =========================================================== Blockchain Alogithm ====================================================================== 


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def compute_hash(self):
        """
        A function that return the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not Blockchain.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    @staticmethod
    def proof_of_work(block):
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        Check if block_hash is valid hash of block and satisfies
        the difficulty criteria.
        """
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            # remove the hash field to recompute the hash again
            # using `compute_hash` method.
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result

    def mine(self):
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding them to the block
        and figuring out Proof Of Work.
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True


#================================================================= Webapp ===============================================================

@app.route('/login' , methods=['GET' , 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        global user
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password , form.password.data):
                
                login_user(user)
                return redirect(url_for('home'))
    user = None
    return render_template('login.html' , form=form)

@app.route('/register' , methods=['GET' , 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data , password=hashed_password , address=form.address.data , key=form.key.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html' , form=form)

def fetch_posts():
    """
    Function to fetch the chain from a blockchain node, parse the
    data and store it locally.
    """
    get_chain_address = "{}/chain".format(CONNECTED_SERVICE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        vote_count = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                content.append(tx)


        global posts
        posts = sorted(content, key=lambda k: k['timestamp'],
                       reverse=True)

@app.route('/' , methods=['GET' , 'POST'])
@login_required
def home():
    fetch_posts()
    vote_check = []

    for post in posts:
        vote_check.append(post["voter_id"])
    if user.id in vote_check:
        return render_template('abort.html')
    return render_template('home.html')

@app.route('/logout' , methods=['GET' , 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


blockchain = Blockchain()
blockchain.create_genesis_block()
peers = set()
vote_check=[]
posts = []


@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["voter_id", "party"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404

    tx_data["timestamp"] = time.time()

    blockchain.add_new_transaction(tx_data)

    return "Success", 201

@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})


@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    peers.add(node_address)

    # Return the consensus blockchain to the newly registered node
    # so that he can sync
    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        # update chain and the peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return "Registration successful", 200
    else:
        # if something goes wrong, pass it on to the API response
        return response.content, response.status_code


def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    generated_blockchain.create_genesis_block()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue  # skip genesis block
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("The chain dump is tampered!!")
    return generated_blockchain


# endpoint to add a block mined by someone else to
# the node's chain. The block is first verified by the node
# and then added to the chain.
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201


# endpoint to query unconfirmed transactions
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)


def consensus():
    """
    Our naive consnsus algorithm. If a longer valid chain is
    found, our chain is replaced with it.
    """
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        response = requests.get('{}chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False


def announce_new_block(block):
    """
    A function to announce to the network once a block has been mined.
    Other blocks can simply verify the proof of work and add it to their
    respective chains.
    """
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)


@app.route('/vote' , methods=['GET' , 'POST'])
@login_required
def vote():
    
    if  request.method == 'POST':
        
        new_tx_address = "{}/new_transaction".format(CONNECTED_SERVICE_ADDRESS)
        if request.form['voteBtn'] == 'AANG':
            post_object = {
            'voter_id': user.id ,
            'party': 'AANG'
            }
            requests.post(new_tx_address,
                          json=post_object,
                          headers={'Content-type': 'application/json'})
        elif request.form['voteBtn'] == 'KORRA':
            post_object = {
            'voter_id': user.id ,
            'party': 'KORRA'
            }
            requests.post(new_tx_address,
                          json=post_object,
                          headers={'Content-type': 'application/json'})

        elif request.form['voteBtn'] == 'ROKU':
            post_object = {
            'voter_id': user.id ,
            'party': 'ROKU'
            }
            requests.post(new_tx_address,
                          json=post_object,
                          headers={'Content-type': 'application/json'})
        
        return redirect(url_for('voted'))
    else:
        return render_template('vote.html')



@app.route('/voted' , methods=['GET' , 'POST'])
def voted():
    result = blockchain.mine()
    if not result:
        return "No transactions to mine"
    else:
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            announce_new_block(blockchain.last_block)
    logout_user()
    return render_template('voted.html')

@app.route('/admin/' , methods=['GET' , 'POST'])
@login_required
def admin():
    form = LoginForm()
    if form.validate_on_submit():
        global user
        user = User.query.filter_by(username=form.username.data).first()
        try:
            if user.username == ADMIN:
                if bcrypt.check_password_hash(user.password , PASSWORD):
                    login_user(user)
                    return redirect(url_for('adminPortal'))
        except:
            abort(403)

    return render_template('adminLogin.html' , form=form)

@app.route('/adminPortal', methods=['GET', 'POST'])
def adminPortal():
    vote_gain = []

    for post in posts:
        vote_gain.append(post["party"])
    
    return render_template('result.html', aang=vote_gain.count('AANG'), korra=vote_gain.count('KORRA'), roku=vote_gain.count('ROKU'))
        

if __name__ == "__main__":
    app.run(host="0.0.0.0" ,port=port, debug = True)

    